package obsidian

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"sync"
	"time"
)

// In-tunnel rekey.
//
// The client periodically runs a fresh X25519 + ML-KEM-768 exchange inside the authenticated
// tunnel; both peers then move TCP and UDP to the keys of the next epoch without reconnecting
// (DeriveRekeyedKeys). This replaces the hard session close: a session lives as long as it
// keeps rekeying, and leaked keys stop being useful after the next epoch.
//
// Messages, all PacketRekey frames:
//
//	INIT  client -> server  [1][epoch u32][client X25519 eph 32][client ML-KEM ek 1184]
//	RESP  server -> client  [2][epoch u32][server X25519 eph 32][ML-KEM ciphertext 1088]
//	FIN   client -> server  [3][epoch u32]
//
// Each direction switches its send keys right after the frame that marks the switch, written
// under the send lock, so no frame of one epoch follows a frame of the next: RESP marks the
// server's switch, FIN the client's. The receiver switches right after parsing that frame.
//
// UDP: the server accepts the new epoch before sending RESP and keeps sending the old one until
// FIN; the client switches both directions after RESP and still accepts the old epoch. Each side
// drops the previous epoch a grace period later.
//
// Compatibility: the server announces support with a NOISE frame whose encrypted payload starts
// with rekeyCapMagic; older clients discard it like any NOISE. A client only sends INIT after
// seeing it, so an older server never receives PacketRekey and keeps its old session lifetime.

const (
	rekeyMsgInit = 1
	rekeyMsgResp = 2
	rekeyMsgFin  = 3

	rekeyHeaderLen = 5
	rekeyInitLen   = rekeyHeaderLen + KeySize + MLKEM768EncapsulationKeySize
	rekeyRespLen   = rekeyHeaderLen + KeySize + MLKEM768CiphertextSize
	rekeyFinLen    = rekeyHeaderLen
)

var rekeyCapMagic = []byte("obsidian-rekey-1")

// RekeyConfig sets the rekey schedule. Zero fields take the defaults.
type RekeyConfig struct {
	// Interval between rekeys started by the client, randomized by ±20%. Default 30 minutes.
	Interval time.Duration
	// Timeout for the server's answer before the client drops the tunnel. Default 30 s.
	Timeout time.Duration
	// Grace keeps the previous UDP epoch acceptable for datagrams still in flight. Default 30 s.
	Grace time.Duration
	// MinInterval is the shortest time between rekeys the server accepts. Default 30 s.
	MinInterval time.Duration
	// AnnounceWithin bounds when the server announces support: at a random moment between
	// 1/30 of it and all of it after the session starts, so no extra record sits at a fixed
	// position right after the handshake. Default 5 minutes, well before the first rekey.
	AnnounceWithin time.Duration
}

func (c RekeyConfig) withDefaults() RekeyConfig {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Minute
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Grace <= 0 {
		c.Grace = 30 * time.Second
	}
	if c.MinInterval <= 0 {
		c.MinInterval = 30 * time.Second
	}
	if c.AnnounceWithin <= 0 {
		c.AnnounceWithin = 5 * time.Minute
	}
	return c
}

// RekeyHooks let the owner of a tunnel move its UDP path along. Any hook may be nil. A hook
// error closes the tunnel.
type RekeyHooks struct {
	// AcceptNext runs on the server before RESP is sent: start accepting the new epoch.
	AcceptNext func(next *SessionKeys) error
	// Commit runs when this side sends with the new keys: on the client after FIN is written
	// (switch UDP both ways), on the server when FIN arrives (switch UDP sending).
	Commit func(next *SessionKeys) error
	// DropPrev runs one grace period after Commit.
	DropPrev func()
}

type tunnelRekey struct {
	isClient bool
	cfg      RekeyConfig
	hooks    RekeyHooks

	mu         sync.Mutex
	keys       *SessionKeys
	epoch      uint32
	lastCommit time.Time
	nextAt      time.Time
	// client: the INIT in flight
	pendEph  *Keypair
	pendKEM  *MLKEMKeypair
	pendInit []byte
	pendAt   time.Time
	// client: RESP processed, FIN not written yet; no new INIT until it is
	finPending bool
	// server: keys sent in RESP, waiting for FIN
	next *SessionKeys
	// kick wakes the client loop when a rekey completes, so it schedules the next one at once.
	kick chan struct{}
}

// EnableRekey turns on in-tunnel rekeying with the keys the handshake produced. Call it once,
// right after NewTunnel and before traffic depends on it. The server announces support to the
// client; the client starts rekeys on its schedule once the server has announced it.
func (t *Tunnel) EnableRekey(keys *SessionKeys, isClient bool, cfg RekeyConfig, hooks RekeyHooks) error {
	if keys == nil {
		return errors.New("rekey needs the session keys")
	}
	own := *keys
	st := &tunnelRekey{isClient: isClient, cfg: cfg.withDefaults(), hooks: hooks, keys: &own, kick: make(chan struct{}, 1)}
	now := time.Now()
	st.lastCommit = now
	st.nextAt = now.Add(jitterRekey(st.cfg.Interval))
	if !t.rekey.CompareAndSwap(nil, st) {
		return errors.New("rekey already enabled")
	}
	if isClient {
		t.wg.Add(1)
		go t.rekeyLoop(st)
		return nil
	}
	span := int64(st.cfg.AnnounceWithin - st.cfg.AnnounceWithin/30)
	delay := st.cfg.AnnounceWithin/30 + time.Duration(rand.Int64N(span+1))
	time.AfterFunc(delay, func() {
		select {
		case <-t.ctx.Done():
			return
		default:
		}
		if err := t.writePacket(PacketNoise, rekeyCapPayload()); err != nil {
			t.cancel()
		}
	})
	return nil
}

// RekeyEpoch reports how many rekeys this tunnel has completed.
func (t *Tunnel) RekeyEpoch() uint32 {
	st := t.rekey.Load()
	if st == nil {
		return 0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.epoch
}

func rekeyCapPayload() []byte {
	// Same size range as an ordinary NOISE payload (NewNoisePacket).
	p := make([]byte, 64+rand.IntN(448))
	FastRandomBytes(p)
	copy(p, rekeyCapMagic)
	return p
}

func jitterRekey(d time.Duration) time.Duration {
	span := d / 5
	if span <= 0 {
		return d
	}
	return d - span + time.Duration(rand.Int64N(int64(2*span)+1))
}

// noteNoise is called by recvLoop for every NOISE frame. The announcement may arrive before the
// client calls EnableRekey, so it is recorded on the tunnel itself.
func (t *Tunnel) noteNoise(payload []byte) {
	if bytes.HasPrefix(payload, rekeyCapMagic) {
		t.peerRekeyCapable.Store(true)
	}
}

func (t *Tunnel) rekeyLoop(st *tunnelRekey) {
	defer t.wg.Done()
	timer := time.NewTimer(time.Until(st.nextAt))
	defer timer.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-timer.C:
		case <-st.kick:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		wait, err := t.rekeyTick(st, time.Now())
		if err != nil {
			log.Printf("tunnel rekey: %v", err)
			t.cancel()
			return
		}
		timer.Reset(wait)
	}
}

// rekeyTick starts a rekey when one is due and returns how long to wait before the next check.
func (t *Tunnel) rekeyTick(st *tunnelRekey, now time.Time) (time.Duration, error) {
	st.mu.Lock()
	if st.pendInit != nil {
		waited := now.Sub(st.pendAt)
		st.mu.Unlock()
		if waited >= st.cfg.Timeout {
			return 0, fmt.Errorf("no answer to rekey after %s", waited.Round(time.Second))
		}
		return st.cfg.Timeout - waited, nil
	}
	if st.finPending {
		st.mu.Unlock()
		return st.cfg.Timeout, nil // the FIN writer kicks the loop when done
	}
	if now.Before(st.nextAt) {
		d := st.nextAt.Sub(now)
		st.mu.Unlock()
		return d, nil
	}
	if !t.peerRekeyCapable.Load() {
		st.nextAt = now.Add(jitterRekey(st.cfg.Interval))
		st.mu.Unlock()
		return st.nextAt.Sub(now), nil
	}
	eph, err := GenerateKeypair()
	if err != nil {
		st.mu.Unlock()
		return 0, err
	}
	kem, err := GenerateMLKEMKeypair()
	if err != nil {
		st.mu.Unlock()
		return 0, err
	}
	msg := make([]byte, 0, rekeyInitLen)
	msg = append(msg, rekeyMsgInit)
	msg = binary.BigEndian.AppendUint32(msg, st.epoch+1)
	msg = append(msg, eph.Public[:]...)
	msg = append(msg, kem.EncapsulationKey.Bytes()...)
	st.pendEph, st.pendKEM, st.pendInit, st.pendAt = eph, kem, msg, now
	timeout := st.cfg.Timeout
	st.mu.Unlock()

	if err := t.writeRekeyFrame(msg); err != nil {
		return 0, err
	}
	return timeout, nil
}

// rekeyFrameSlack is the extra room appendRekeyFrames needs beyond the payload.
const rekeyFrameSlack = 2*(4+packetHeaderSize+256+TagSize) + hsNoiseMax

// appendRekeyFrames writes a NOISE frame and then the PacketRekey frame with random padding, so
// the rekey messages do not have a fixed size on the wire. The NOISE frame goes first because
// RESP and FIN end the sender's epoch: nothing may follow them under the old keys.
func (t *Tunnel) appendRekeyFrames(dst, payload []byte) (int, error) {
	pad, noise := handshakePadPlan()
	n, err := t.appendNoiseFrame(dst, noise)
	if err != nil {
		return 0, err
	}
	m, err := t.framer.FrameWithPadding(dst[n:], PacketRekey, payload, pad, pad)
	if err != nil {
		return 0, err
	}
	return n + m, nil
}

// writeRekeyFrame sends a rekey message that does not switch keys (INIT).
func (t *Tunnel) writeRekeyFrame(payload []byte) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	rawBuf := getFrameBuf(len(payload) + rekeyFrameSlack)
	defer putFrameBuf(rawBuf)
	n, err := t.appendRekeyFrames(*rawBuf, payload)
	if err != nil {
		return err
	}
	if err := t.writeFrameLocked((*rawBuf)[:n]); err != nil {
		t.cancel()
		return err
	}
	t.lastAuthNano.Store(time.Now().UnixNano())
	return nil
}

// handleRekey processes one PacketRekey frame on the recvLoop goroutine, so the receive-side
// key switch happens before the next frame is parsed. An error closes the tunnel.
func (t *Tunnel) handleRekey(msg []byte) error {
	st := t.rekey.Load()
	if st == nil {
		return errors.New("rekey message but rekey is not enabled")
	}
	if len(msg) < rekeyHeaderLen {
		return errors.New("short rekey message")
	}
	epoch := binary.BigEndian.Uint32(msg[1:5])
	switch {
	case msg[0] == rekeyMsgInit && !st.isClient && len(msg) == rekeyInitLen:
		return t.handleRekeyInit(st, epoch, msg)
	case msg[0] == rekeyMsgResp && st.isClient && len(msg) == rekeyRespLen:
		return t.handleRekeyResp(st, epoch, msg)
	case msg[0] == rekeyMsgFin && !st.isClient && len(msg) == rekeyFinLen:
		return t.handleRekeyFin(st, epoch)
	default:
		return fmt.Errorf("unexpected rekey message %d (%d bytes)", msg[0], len(msg))
	}
}

func (t *Tunnel) handleRekeyInit(st *tunnelRekey, epoch uint32, msg []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.next != nil {
		return errors.New("rekey started while another is in progress")
	}
	if epoch != st.epoch+1 {
		return fmt.Errorf("rekey epoch %d, want %d", epoch, st.epoch+1)
	}
	if time.Since(st.lastCommit) < st.cfg.MinInterval {
		return errors.New("rekey requested too often")
	}
	var clientEph [KeySize]byte
	copy(clientEph[:], msg[rekeyHeaderLen:rekeyHeaderLen+KeySize])
	eph, err := GenerateKeypair()
	if err != nil {
		return err
	}
	defer eph.Zero()
	ssX, err := DHSafe(eph.Private, clientEph)
	if err != nil {
		return err
	}
	defer clear(ssX[:])
	ssK, ct, err := EncapsulateMLKEM(msg[rekeyHeaderLen+KeySize:])
	if err != nil {
		return err
	}
	defer clear(ssK)

	resp := make([]byte, 0, rekeyRespLen)
	resp = append(resp, rekeyMsgResp)
	resp = binary.BigEndian.AppendUint32(resp, epoch)
	resp = append(resp, eph.Public[:]...)
	resp = append(resp, ct...)

	next, err := DeriveRekeyedKeys(st.keys, epoch, ssX[:], ssK, rekeyTranscript(msg, resp))
	if err != nil {
		return err
	}
	if st.hooks.AcceptNext != nil {
		if err := st.hooks.AcceptNext(next); err != nil {
			return fmt.Errorf("accept next epoch: %w", err)
		}
	}
	st.next = next
	enc, err := NewCipher(next.ServerKey, next.ServerIV)
	if err != nil {
		return err
	}
	_, serverHeader := DeriveTCPHeaderKeys(next)
	// Written from another goroutine: recvLoop must keep reading while a large send is blocked,
	// or two peers busy sending to each other could both stop reading.
	go t.sendMarkerAndSwitch(resp, enc, serverHeader, nil)
	return nil
}

func (t *Tunnel) handleRekeyResp(st *tunnelRekey, epoch uint32, msg []byte) error {
	st.mu.Lock()
	if st.pendInit == nil {
		st.mu.Unlock()
		return errors.New("rekey answer without a request")
	}
	if epoch != st.epoch+1 {
		st.mu.Unlock()
		return fmt.Errorf("rekey answer for epoch %d, want %d", epoch, st.epoch+1)
	}
	var serverEph [KeySize]byte
	copy(serverEph[:], msg[rekeyHeaderLen:rekeyHeaderLen+KeySize])
	ssX, err := DHSafe(st.pendEph.Private, serverEph)
	if err != nil {
		st.mu.Unlock()
		return err
	}
	ssK, err := DecapsulateMLKEM(st.pendKEM.DecapsulationKey, msg[rekeyHeaderLen+KeySize:])
	if err != nil {
		st.mu.Unlock()
		return err
	}
	next, err := DeriveRekeyedKeys(st.keys, epoch, ssX[:], ssK, rekeyTranscript(st.pendInit, msg))
	clear(ssX[:])
	clear(ssK)
	st.pendEph.Zero()
	st.pendEph, st.pendKEM, st.pendInit = nil, nil, nil
	if err != nil {
		st.mu.Unlock()
		return err
	}
	dec, err := NewCipher(next.ServerKey, next.ServerIV)
	if err != nil {
		st.mu.Unlock()
		return err
	}
	enc, err := NewCipher(next.ClientKey, next.ClientIV)
	if err != nil {
		st.mu.Unlock()
		return err
	}
	clientHeader, serverHeader := DeriveTCPHeaderKeys(next)
	// Every frame after RESP is sealed with the server's new keys.
	t.framer.setDecKeys(dec, serverHeader)
	st.keys.Zero()
	st.keys, st.epoch, st.finPending = next, epoch, true
	t.startEpoch(st)
	st.mu.Unlock()

	fin := binary.BigEndian.AppendUint32([]byte{rekeyMsgFin}, epoch)
	go t.sendMarkerAndSwitch(fin, enc, clientHeader, func() {
		st.mu.Lock()
		st.finPending = false
		st.mu.Unlock()
		t.commitEpoch(st, epoch, next)
		select {
		case st.kick <- struct{}{}:
		default:
		}
	})
	return nil
}

func (t *Tunnel) handleRekeyFin(st *tunnelRekey, epoch uint32) error {
	st.mu.Lock()
	next := st.next
	if next == nil || epoch != st.epoch+1 {
		st.mu.Unlock()
		return fmt.Errorf("unexpected rekey finish for epoch %d", epoch)
	}
	dec, err := NewCipher(next.ClientKey, next.ClientIV)
	if err != nil {
		st.mu.Unlock()
		return err
	}
	clientHeader, _ := DeriveTCPHeaderKeys(next)
	// FIN was the client's last frame under the old keys.
	t.framer.setDecKeys(dec, clientHeader)
	st.keys.Zero()
	st.keys, st.epoch, st.next = next, epoch, nil
	t.startEpoch(st)
	st.mu.Unlock()
	t.commitEpoch(st, epoch, next)
	return nil
}

// startEpoch resets the session lifetime counters. Caller holds st.mu.
func (t *Tunnel) startEpoch(st *tunnelRekey) {
	now := time.Now()
	st.lastCommit = now
	st.nextAt = now.Add(jitterRekey(st.cfg.Interval))
	t.epochStartNano.Store(now.UnixNano())
	t.epochStartPackets.Store(t.packetCount.Load())
}

// commitEpoch runs the Commit hook and schedules DropPrev. A drop scheduled for an epoch that a
// later rekey has already replaced is skipped: by then the previous epoch is a different one.
func (t *Tunnel) commitEpoch(st *tunnelRekey, epoch uint32, next *SessionKeys) {
	if st.hooks.Commit != nil {
		if err := st.hooks.Commit(next); err != nil {
			log.Printf("tunnel rekey commit: %v", err)
			t.cancel()
			return
		}
	}
	if st.hooks.DropPrev != nil {
		time.AfterFunc(st.cfg.Grace, func() {
			select {
			case <-t.ctx.Done():
				return
			default:
			}
			st.mu.Lock()
			current := st.epoch == epoch && st.next == nil
			st.mu.Unlock()
			if current {
				st.hooks.DropPrev()
			}
		})
	}
}

// sendMarkerAndSwitch writes the frame that ends this side's current epoch and switches the
// send keys before any other frame can follow, then runs after.
func (t *Tunnel) sendMarkerAndSwitch(payload []byte, enc *Cipher, headerKey [KeySize]byte, after func()) {
	t.sendMu.Lock()
	rawBuf := getFrameBuf(len(payload) + rekeyFrameSlack)
	n, err := t.appendRekeyFrames(*rawBuf, payload)
	if err == nil {
		err = t.writeFrameLocked((*rawBuf)[:n])
	}
	putFrameBuf(rawBuf)
	if err == nil {
		t.framer.setEncKeys(enc, headerKey)
	}
	t.sendMu.Unlock()
	if err != nil {
		log.Printf("tunnel rekey send: %v", err)
		t.cancel()
		return
	}
	if after != nil {
		after()
	}
}

func rekeyTranscript(init, resp []byte) []byte {
	out := make([]byte, 0, len(init)+len(resp))
	out = append(out, init...)
	return append(out, resp...)
}

// setEncKeys switches the send direction to a new epoch. Caller holds the tunnel send lock.
func (f *StreamFramer) setEncKeys(c *Cipher, headerKey [KeySize]byte) {
	hk := headerKey
	f.EncCipher, f.EncHeaderKey, f.EncFrameKey, f.encFrameCtr = c, &hk, &hk, 0
}

// setDecKeys switches the receive direction to a new epoch. Only recvLoop calls it.
func (f *StreamFramer) setDecKeys(c *Cipher, headerKey [KeySize]byte) {
	hk := headerKey
	f.DecCipher, f.DecHeaderKey, f.DecFrameKey, f.decFrameCtr = c, &hk, &hk, 0
}
