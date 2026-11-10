package obsidian

// ── Obfuscation / Tunnel ──────────────────────────────────────────────────────
//
// Улучшения v2:
//   - Исправлен nil context panic в RecvData
//   - time.After → time.NewTimer (нет утечки таймеров)
//   - sync.Pool для буферов входящих фреймов (нет аллокации на каждый пакет)
//   - Rate limiter на количество handshake (защита от DDoS X25519)
//   - Настраиваемый S4 padding диапазон передаётся через TunnelConfig

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── JitterProfile ─────────────────────────────────────────────────────────────

type JitterProfile int

const (
	JitterOff    JitterProfile = iota
	JitterLight                // 0–5ms
	JitterMedium               // 0–20ms
	JitterHeavy                // 0–50ms
)

// window returns the maximum delay of the profile, or 0 when jitter is off.
func (j JitterProfile) window() time.Duration {
	switch j {
	case JitterLight:
		return 5 * time.Millisecond
	case JitterMedium:
		return 20 * time.Millisecond
	case JitterHeavy:
		return 50 * time.Millisecond
	default:
		return 0
	}
}

func (j JitterProfile) sleep() {
	maxDelay := j.window()
	if maxDelay <= 0 {
		return
	}
	delay := time.Duration(rand.Float64() * float64(maxDelay))
	if delay > 0 {
		time.Sleep(delay)
	}
}

// ── TunnelConfig ──────────────────────────────────────────────────────────────

type TunnelConfig struct {
	NoiseMinInterval   time.Duration
	NoiseMaxInterval   time.Duration
	KeepaliveInterval  time.Duration
	KeepaliveJitter    time.Duration
	MaxSessionDuration time.Duration
	MaxSessionPackets  uint64
	Jitter             JitterProfile
	DataPadMin         int
	DataPadMax         int
	UseBucketPadding   bool
	BucketMTU          int
	MaxTrailer         int
	// HandshakePadding pads DATA packets that start a TLS handshake and follows them with a NOISE
	// frame, within a byte budget (see handshake_padding.go). Peers need no support for it.
	HandshakePadding bool
}

const tunnelWriteTimeout = 30 * time.Second

const (
	defaultMaxSessionDuration = 6 * time.Hour
	defaultMaxSessionPackets  = uint64(1) << 48
)

func DefaultTunnelConfig() TunnelConfig {
	return TunnelConfig{
		NoiseMinInterval:   10 * time.Second,
		NoiseMaxInterval:   40 * time.Second,
		KeepaliveInterval:  20 * time.Second,
		KeepaliveJitter:    5 * time.Second,
		MaxSessionDuration: defaultMaxSessionDuration,
		MaxSessionPackets:  defaultMaxSessionPackets,
		Jitter:             JitterOff,
		DataPadMin:         0,
		DataPadMax:         0,
		UseBucketPadding:   false,
		BucketMTU:          1360,
		MaxTrailer:         0,
		HandshakePadding:   true,
	}
}

// CalculateBucketPaddingWithTrailer computes the padding size required to align payloadLen
// to discrete bucket sizes (64, 256, 512, 1024, maxMTU) with a dynamic pseudo-random
// trailer [0, maxTrailer] to smear discrete packet length distributions (AmneziaWG 3.1),
// while strictly guaranteeing payloadLen + padding <= maxMTU.
func CalculateBucketPaddingWithTrailer(payloadLen, maxMTU, maxTrailer int) int {
	if payloadLen <= 0 || payloadLen >= maxMTU {
		return 0
	}
	buckets := [...]int{64, 256, 512, 1024}
	basePad := 0
	found := false
	for _, b := range buckets {
		if payloadLen <= b {
			basePad = b - payloadLen
			found = true
			break
		}
	}
	if !found {
		if maxMTU > 1024 && payloadLen < maxMTU {
			basePad = maxMTU - payloadLen
		} else {
			return 0
		}
	}
	trailer := 0
	if maxTrailer >= 4 {
		maxSteps := maxTrailer / 4
		trailer = rand.IntN(maxSteps+1) * 4
	}
	pad := basePad + trailer
	if payloadLen+pad > maxMTU {
		pad = maxMTU - payloadLen
	}
	// Strict RFC 5389 requirement: ensure total length (payloadLen + pad) is 4-byte aligned
	rem := (payloadLen + pad) % 4
	if rem != 0 {
		pad += (4 - rem)
		if payloadLen+pad > maxMTU && maxMTU >= 4 {
			pad -= 4
		}
	}
	if pad < 0 {
		pad = 0
	}
	return pad
}

// CalculateBucketPadding computes the padding size required to align payloadLen
// to discrete bucket sizes (64, 256, 512, 1024, maxMTU) without exceeding maxMTU.
func CalculateBucketPadding(payloadLen, maxMTU int) int {
	return CalculateBucketPaddingWithTrailer(payloadLen, maxMTU, 0)
}

// ── Buffer pool ───────────────────────────────────────────────────────────────

var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

func getFrameBuf(size int) *[]byte {
	p := framePool.Get().(*[]byte)
	if cap(*p) >= size {
		*p = (*p)[:size]
		return p
	}
	framePool.Put(p)
	b := make([]byte, size)
	return &b
}

func putFrameBuf(p *[]byte) {
	if p != nil && cap(*p) >= 4096 && cap(*p) <= 65536+1024 {
		*p = (*p)[:0]
		framePool.Put(p)
	}
}

var tunnelPayloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func getTunnelPayload(size int) *[]byte {
	p := tunnelPayloadPool.Get().(*[]byte)
	if cap(*p) >= size {
		*p = (*p)[:size]
		return p
	}
	tunnelPayloadPool.Put(p)
	b := make([]byte, size)
	return &b
}

func putTunnelPayload(p *[]byte) {
	if p != nil && cap(*p) >= 2048 && cap(*p) <= 65536+1024 {
		*p = (*p)[:0]
		tunnelPayloadPool.Put(p)
	}
}

// ── Rate limiter ──────────────────────────────────────────────────────────────

// HandshakeRateLimiter ограничивает количество одновременных handshake.
// X25519 стоит ~0.1ms — без лимита 10k соединений/сек = 100% CPU.
type HandshakeRateLimiter struct {
	active atomic.Int64
	max    int64
}

func NewHandshakeRateLimiter(maxConcurrent int) *HandshakeRateLimiter {
	return &HandshakeRateLimiter{max: int64(maxConcurrent)}
}

// Acquire возвращает false если лимит превышен.
func (r *HandshakeRateLimiter) Acquire() bool {
	for {
		cur := r.active.Load()
		if cur >= r.max {
			return false
		}
		if r.active.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (r *HandshakeRateLimiter) Release() {
	r.active.Add(-1)
}

// ── Tunnel ────────────────────────────────────────────────────────────────────

type tunnelPkt struct {
	buf *[]byte
	n   int
}

type Tunnel struct {
	conn   net.Conn
	reader *bufio.Reader
	framer *StreamFramer
	jitter JitterProfile
	// writeDeadlineAt is when the write deadline was last pushed forward, guarded by sendMu.
	writeDeadlineAt time.Time
	// batchBuf collects the frames of one SendDataBatch call, guarded by sendMu.
	batchBuf []byte

	dataIn       chan tunnelPkt
	sendMu       sync.Mutex
	lastAuthNano atomic.Int64
	// lastDataSendNano is the time of the previous DATA send; used to detect bursts for jitter.
	lastDataSendNano atomic.Int64
	createdAt        time.Time
	maxDuration      time.Duration
	maxPackets       uint64
	packetCount      atomic.Uint64
	hsPad            bool
	// The session lifetime limits count from the start of the current key epoch, so a tunnel
	// that rekeys (rekey.go) is never closed by them.
	epochStartNano    atomic.Int64
	epochStartPackets atomic.Uint64
	rekey             atomic.Pointer[tunnelRekey]
	peerRekeyCapable  atomic.Bool
	hsBudget         handshakePadBudget // guarded by sendMu

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// tunnelDataQueueSize bounds decrypted DATA packets buffered between recvLoop and the
// consumer. When full, recvLoop blocks (backpressure to the outer stream), so this only
// limits local queueing delay: 256 x 1.3 KB is ~100 ms at 20 Mbps versus ~0.5 s at 1024.
const tunnelDataQueueSize = 256

// tunnelReadBufSize lets recvLoop take the length prefix and the frame body of several frames
// from one read instead of two reads per frame.
const tunnelReadBufSize = 32 * 1024

// tunnelBatchLimit flushes a SendDataBatch buffer once it holds this much.
const tunnelBatchLimit = 64 * 1024

func NewTunnel(conn net.Conn, framer *StreamFramer, cfg TunnelConfig) *Tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	dynDuration := cfg.MaxSessionDuration
	if dynDuration > 0 {
		// Dynamic session lifetime deperiodization: BaseInterval ± rand(1..5m)
		jitterMin := time.Duration(1+rand.IntN(5)) * time.Minute
		if rand.Float64() < 0.5 {
			dynDuration -= jitterMin
		} else {
			dynDuration += jitterMin
		}
		if dynDuration < time.Minute {
			dynDuration = time.Minute
		}
	}
	t := &Tunnel{
		conn:        conn,
		reader:      bufio.NewReaderSize(conn, tunnelReadBufSize),
		framer:      framer,
		jitter:      cfg.Jitter,
		dataIn:      make(chan tunnelPkt, tunnelDataQueueSize),
		createdAt:   now,
		maxDuration: dynDuration,
		maxPackets:  cfg.MaxSessionPackets,
		hsPad:       cfg.HandshakePadding,
		ctx:         ctx,
		cancel:      cancel,
	}
	t.lastAuthNano.Store(now.UnixNano())
	t.epochStartNano.Store(now.UnixNano())

	t.framer.PaddingCfg.DataMin = cfg.DataPadMin
	t.framer.PaddingCfg.DataMax = cfg.DataPadMax
	t.framer.PaddingCfg.UseBucketPadding = cfg.UseBucketPadding
	t.framer.PaddingCfg.BucketMTU = cfg.BucketMTU
	t.framer.PaddingCfg.MaxTrailer = cfg.MaxTrailer

	t.wg.Add(3)
	go t.recvLoop()
	go t.noiseLoop(cfg.NoiseMinInterval, cfg.NoiseMaxInterval)
	go t.keepaliveLoop(cfg.KeepaliveInterval, cfg.KeepaliveJitter)

	return t
}

// SendData отправляет IP пакет через туннель.
func (t *Tunnel) SendData(payload []byte) error {
	if t.hsPad && LooksLikeTLSHandshake(payload) {
		_, err := t.SendDataBatch([][]byte{payload})
		return err
	}
	t.applyBurstJitter()
	return t.writePacket(PacketData, payload)
}

// SendDataBatch frames each packet exactly as SendData does and writes the frames together,
// so a burst costs one write instead of one per packet. The byte stream is the concatenation of
// the same frames; only how the kernel cuts it into segments changes. It returns how many
// packets were written.
func (t *Tunnel) SendDataBatch(packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	t.applyBurstJitter()
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	buf := t.batchBuf[:0]
	framed, sent := 0, 0
	flush := func() error {
		if len(buf) == 0 {
			return nil
		}
		if err := t.writeFrameLocked(buf); err != nil {
			t.cancel()
			return err
		}
		sent = framed
		buf = buf[:0]
		return nil
	}
	defer func() { t.batchBuf = buf[:0] }()

	for _, p := range packets {
		if t.sessionExpired(t.packetCount.Add(1)) {
			t.cancel()
			if err := flush(); err != nil {
				return sent, err
			}
			return sent, io.ErrClosedPipe
		}
		need := 4 + packetHeaderSize + len(p) + 256 + TagSize
		pad, noise := 0, 0
		if t.hsPad && LooksLikeTLSHandshake(p) {
			pad, noise = handshakePadPlan()
			if t.hsBudget.take(pad+noise+4+packetHeaderSize+TagSize, time.Now()) {
				need += 4 + packetHeaderSize + noise + 256 + TagSize
			} else {
				pad, noise = 0, 0
			}
		}
		if len(buf) > 0 && len(buf)+need > tunnelBatchLimit {
			if err := flush(); err != nil {
				return sent, err
			}
		}
		if cap(buf)-len(buf) < need {
			grown := make([]byte, len(buf), max(len(buf)+need, tunnelBatchLimit))
			copy(grown, buf)
			buf = grown
		}
		var n int
		var err error
		if pad > 0 {
			n, err = t.framer.FrameWithPadding(buf[len(buf):len(buf)+need], PacketData, p, pad, pad)
			if err == nil {
				var m int
				m, err = t.appendNoiseFrame(buf[len(buf)+n:len(buf)+need], noise)
				n += m
			}
		} else {
			n, err = t.framer.FrameWithBuffer(buf[len(buf):len(buf)+need], PacketData, p)
		}
		if err != nil {
			if ferr := flush(); ferr != nil {
				return sent, ferr
			}
			return sent, err
		}
		buf = buf[:len(buf)+n]
		framed++
	}
	if err := flush(); err != nil {
		return sent, err
	}
	t.lastAuthNano.Store(time.Now().UnixNano())
	return sent, nil
}

// appendNoiseFrame writes a NOISE frame with a random payload of size bytes into dst.
func (t *Tunnel) appendNoiseFrame(dst []byte, size int) (int, error) {
	var payload [hsNoiseMax]byte
	FastRandomBytes(payload[:size])
	return t.framer.FrameWithBuffer(dst, PacketNoise, payload[:size])
}

// applyBurstJitter delays the first DATA packet of a burst instead of every packet.
// A per-packet sleep (up to 50 ms under JitterHeavy) caps throughput at roughly
// 1/avg(delay) packets per second and stalls the TUN reader. A burst is a run of
// sends with gaps shorter than the jitter window, so bulk transfers are not
// throttled while sparse or interactive packets still get timing jitter.
func (t *Tunnel) applyBurstJitter() {
	window := t.jitter.window()
	if window <= 0 {
		return
	}
	now := time.Now().UnixNano()
	prev := t.lastDataSendNano.Swap(now)
	if now-prev < int64(window) {
		return
	}
	t.jitter.sleep()
}

// RecvDataInto читает следующий DATA пакет напрямую в dst без промежуточных аллокаций.
func (t *Tunnel) RecvDataInto(ctx context.Context, dst []byte) (int, error) {
	var (
		pkt tunnelPkt
		ok  bool
	)
	if ctx == nil {
		select {
		case pkt, ok = <-t.dataIn:
			if !ok {
				return 0, io.EOF
			}
		case <-t.ctx.Done():
			return 0, io.EOF
		}
	} else {
		select {
		case pkt, ok = <-t.dataIn:
			if !ok {
				return 0, io.EOF
			}
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-t.ctx.Done():
			return 0, io.EOF
		}
	}
	defer putTunnelPayload(pkt.buf)
	if len(dst) < pkt.n {
		return 0, io.ErrShortBuffer
	}
	copy(dst, (*pkt.buf)[:pkt.n])
	return pkt.n, nil
}

// RecvData блокируется до получения следующего DATA пакета.
// ctx может быть nil — тогда используется только внутренний контекст туннеля.
func (t *Tunnel) RecvData(ctx context.Context) ([]byte, error) {
	var (
		pkt tunnelPkt
		ok  bool
	)
	if ctx == nil {
		select {
		case pkt, ok = <-t.dataIn:
			if !ok {
				return nil, io.EOF
			}
		case <-t.ctx.Done():
			return nil, io.EOF
		}
	} else {
		select {
		case pkt, ok = <-t.dataIn:
			if !ok {
				return nil, io.EOF
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.ctx.Done():
			return nil, io.EOF
		}
	}
	defer putTunnelPayload(pkt.buf)
	data := make([]byte, pkt.n)
	copy(data, (*pkt.buf)[:pkt.n])
	return data, nil
}

// Close завершает туннель.
func (t *Tunnel) Close() error {
	t.cancel()
	err := t.conn.Close()
	t.wg.Wait()
	t.drainDataIn()
	return err
}

func (t *Tunnel) drainDataIn() {
	for {
		select {
		case pkt, ok := <-t.dataIn:
			if !ok {
				return
			}
			putTunnelPayload(pkt.buf)
		default:
			return
		}
	}
}

func (t *Tunnel) Done() <-chan struct{} {
	return t.ctx.Done()
}

func (t *Tunnel) sessionExpired(count uint64) bool {
	if count&1023 != 0 {
		return false
	}
	if t.maxDuration > 0 && time.Since(time.Unix(0, t.epochStartNano.Load())) >= t.maxDuration {
		return true
	}
	if t.maxPackets > 0 && count-t.epochStartPackets.Load() >= t.maxPackets {
		return true
	}
	return false
}

func packetTypeName(pt PacketType) string {
	switch pt {
	case PacketData:
		return "DATA"
	case PacketNoise:
		return "NOISE"
	case PacketKeepalive:
		return "KEEPALIVE"
	case PacketClose:
		return "CLOSE"
	default:
		return "UNKNOWN"
	}
}

func (t *Tunnel) writePacket(ptype PacketType, payload []byte) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	count := t.packetCount.Add(1)
	if t.sessionExpired(count) {
		t.cancel()
		return io.ErrClosedPipe
	}

	rawBuf := getFrameBuf(4 + packetHeaderSize + len(payload) + 256 + TagSize)
	defer putFrameBuf(rawBuf)

	n, err := t.framer.FrameWithBuffer(*rawBuf, ptype, payload)
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

func (t *Tunnel) writeFrameLocked(frame []byte) error {
	// The deadline only has to bound a stuck write, so it is pushed forward at most once a
	// second rather than set and cleared around every frame. A write can therefore block for
	// between tunnelWriteTimeout-1s and tunnelWriteTimeout before failing. Nothing else writes
	// to conn once the tunnel exists, so the deadline left in place affects no one.
	if tunnelWriteTimeout > 0 {
		if now := time.Now(); now.Sub(t.writeDeadlineAt) >= time.Second {
			_ = t.conn.SetWriteDeadline(now.Add(tunnelWriteTimeout))
			t.writeDeadlineAt = now
		}
	}
	for len(frame) > 0 {
		n, err := t.conn.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		if n > len(frame) {
			return errors.New("connection write exceeded frame length")
		}
		frame = frame[n:]
	}
	return nil
}

// recvLoop читает фреймы из conn, использует sync.Pool буферы.
func (t *Tunnel) recvLoop() {
	defer t.wg.Done()
	defer t.cancel()
	defer close(t.dataIn)

	lenBuf := make([]byte, 4)
	for {
		count := t.packetCount.Add(1)
		if t.sessionExpired(count) {
			return
		}
		if _, err := io.ReadFull(t.reader, lenBuf); err != nil {
			// EOF/net.ErrClosed is the normal result when the peer or local caller
			// closes a completed tunnel.  Do not turn a successful probe shutdown
			// into a misleading error line.
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("tunnel recv read len failed: %v", err)
			return
		}
		maskedLen := binary.BigEndian.Uint32(lenBuf)
		frameLen := t.framer.DecodeFrameLen(maskedLen)
		if frameLen > uint32(maxFrameSize) {
			log.Printf("tunnel recv invalid frame len: %d", frameLen)
			return
		}

		rawBuf := getFrameBuf(int(frameLen))
		raw := *rawBuf
		if _, err := io.ReadFull(t.reader, raw); err != nil {
			log.Printf("tunnel recv read frame len=%d failed: %v", frameLen, err)
			putFrameBuf(rawBuf)
			return
		}

		pBuf := getTunnelPayload(int(frameLen))
		ptype, payLen, err := t.framer.ParseFrameInto(*pBuf, raw)
		putFrameBuf(rawBuf)
		if err != nil {
			putTunnelPayload(pBuf)
			log.Printf("tunnel recv parse frame len=%d failed: %v", frameLen, err)
			return // аутентификация не прошла
		}

		t.lastAuthNano.Store(time.Now().UnixNano())

		switch ptype {
		case PacketData:
			select {
			case t.dataIn <- tunnelPkt{buf: pBuf, n: payLen}:
			case <-t.ctx.Done():
				putTunnelPayload(pBuf)
				return
			}
		case PacketClose:
			putTunnelPayload(pBuf)
			return
		case PacketRekey:
			err := t.handleRekey((*pBuf)[:payLen])
			putTunnelPayload(pBuf)
			if err != nil {
				log.Printf("tunnel rekey: %v", err)
				return
			}
		case PacketNoise:
			t.noteNoise((*pBuf)[:payLen])
			putTunnelPayload(pBuf)
		default:
			putTunnelPayload(pBuf)
		}
	}
}

// noiseLoop — time.NewTimer вместо time.After (нет утечки).
func (t *Tunnel) noiseLoop(minInterval, maxInterval time.Duration) {
	defer t.wg.Done()
	timer := time.NewTimer(randInterval(minInterval, maxInterval))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			now := time.Now()
			last := time.Unix(0, t.lastAuthNano.Load())
			if maxInterval > 0 && now.Sub(last) < maxInterval {
				timer.Reset(randInterval(minInterval, maxInterval))
				continue
			}
			pkt, err := NewNoisePacket()
			if err == nil {
				if err := t.writePacket(pkt.Type, pkt.Payload); err != nil {
					return
				}
			}
			timer.Reset(randInterval(minInterval, maxInterval))
		case <-t.ctx.Done():
			return
		}
	}
}

// keepaliveLoop — time.NewTimer вместо time.After.
func (t *Tunnel) keepaliveLoop(interval, jitter time.Duration) {
	defer t.wg.Done()
	timer := time.NewTimer(randIntervalJitter(interval, jitter))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			now := time.Now()
			last := time.Unix(0, t.lastAuthNano.Load())
			if interval > 0 {
				quietFor := now.Sub(last)
				if quietFor < interval {
					timer.Reset(interval - quietFor + randIntervalJitter(0, jitter))
					continue
				}
			}
			pkt, err := NewKeepalivePacket()
			if err == nil {
				if err := t.writePacket(pkt.Type, pkt.Payload); err != nil {
					return
				}
			}
			timer.Reset(randIntervalJitter(interval, jitter))
		case <-t.ctx.Done():
			return
		}
	}
}

func randInterval(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Float64()*float64(max-min))
}

func randIntervalJitter(base, jitter time.Duration) time.Duration {
	d := base + time.Duration((rand.Float64()*2-1)*float64(jitter))
	if d < time.Second {
		d = time.Second
	}
	return d
}
