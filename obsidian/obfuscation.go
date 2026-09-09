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

func (j JitterProfile) sleep() {
	var maxMs float64
	switch j {
	case JitterLight:
		maxMs = 5
	case JitterMedium:
		maxMs = 20
	case JitterHeavy:
		maxMs = 50
	default:
		return
	}
	delay := time.Duration(rand.Float64() * maxMs * float64(time.Millisecond))
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
}

const tunnelWriteTimeout = 15 * time.Second

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
	framer *StreamFramer
	jitter JitterProfile

	dataIn       chan tunnelPkt
	sendMu       sync.Mutex
	lastAuthNano atomic.Int64
	createdAt    time.Time
	maxDuration  time.Duration
	maxPackets   uint64
	packetCount  atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

const tunnelDataQueueSize = 1024

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
		framer:      framer,
		jitter:      cfg.Jitter,
		dataIn:      make(chan tunnelPkt, tunnelDataQueueSize),
		createdAt:   now,
		maxDuration: dynDuration,
		maxPackets:  cfg.MaxSessionPackets,
		ctx:         ctx,
		cancel:      cancel,
	}
	t.lastAuthNano.Store(now.UnixNano())

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
	t.jitter.sleep() // вне мьютекса — не блокирует noise/keepalive
	return t.writePacket(PacketData, payload)
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
	if t.maxDuration > 0 && time.Since(t.createdAt) >= t.maxDuration {
		return true
	}
	if t.maxPackets > 0 && count >= t.maxPackets {
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
	if tunnelWriteTimeout > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(tunnelWriteTimeout))
		defer t.conn.SetWriteDeadline(time.Time{}) //nolint:errcheck
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
		if _, err := io.ReadFull(t.conn, lenBuf); err != nil {
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
		if _, err := io.ReadFull(t.conn, raw); err != nil {
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
