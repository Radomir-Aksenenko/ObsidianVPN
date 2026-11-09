package obsidian

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	upstream "github.com/xtls/reality"
	xnet "github.com/xtls/xray-core/common/net"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
)

const TransportNativeReality = "native-reality"

func (cfg ClientConfig) ValidateTransport() error {
	if cfg.Transport == "" {
		return nil
	}
	if cfg.Transport != TransportNativeReality {
		return fmt.Errorf("unknown transport %q", cfg.Transport)
	}
	if cfg.NoTLS || cfg.RealityLegacyFallback {
		return errors.New("native REALITY cannot use no_tls or legacy fallback")
	}
	if _, err := DecodeRealityKey(cfg.RealityPublicKey); err != nil {
		return err
	}
	if _, err := DecodeRealityShortID(cfg.RealityShortID); err != nil {
		return err
	}
	if cfg.RealitySNI == "" && cfg.SNI == "" {
		return errors.New("native REALITY requires an explicit SNI")
	}
	if cfg.AllowDirectUDP {
		secret, err := hex.DecodeString(cfg.RealityAuthKey)
		if err != nil {
			secret = []byte(cfg.RealityAuthKey)
		}
		if len(secret) < 16 {
			return errors.New("direct UDP requires a separate secret reality_auth_key of at least 16 bytes")
		}
	}
	if cfg.AllowDirectUDP && cfg.MTU > 1420 {
		return errors.New("native direct UDP requires inner MTU <=1420 to leave room for IPv6 encapsulation and padding")
	}
	return nil
}

// DirectUDPEnabled makes bypassing the TLS cover an explicit decision in native
// mode. A TCP-only network must never cause an automatic downgrade to raw UDP.
func (cfg ClientConfig) DirectUDPEnabled() bool {
	return cfg.EnableUDPData && cfg.UDPPort != "" && (cfg.Transport != TransportNativeReality || cfg.AllowDirectUDP)
}

// NativeRealityConn is a completed upstream TLS connection, not the experimental
// v5 PSK record camouflage. The inner Obsidian handshake remains independent.
type nativeRealityConn struct{ net.Conn }

func NativeRealityMode(conn net.Conn) bool {
	_, ok := conn.(*nativeRealityConn)
	return ok
}

// DecodeRealityKey accepts the standard REALITY base64url key or our hex config.
func DecodeRealityKey(value string) ([]byte, error) {
	if b, err := hex.DecodeString(value); err == nil && len(b) == 32 {
		return b, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) != 32 {
		return nil, errors.New("REALITY key must be 32 bytes encoded as hex or unpadded base64url")
	}
	return b, nil
}

func DecodeRealityShortID(value string) ([8]byte, error) {
	var id [8]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != len(id) {
		return id, errors.New("REALITY short ID must contain exactly 16 hex characters")
	}
	copy(id[:], b)
	return id, nil
}

// DialNativeReality delegates TLS, authentication, certificate verification and
// current browser fingerprinting to the pinned upstream Xray implementation.
func DialNativeReality(ctx context.Context, cfg ClientTransportConfig, publicKey, shortID, fingerprint string) (net.Conn, error) {
	key, err := DecodeRealityKey(publicKey)
	if err != nil {
		return nil, err
	}
	id, err := DecodeRealityShortID(shortID)
	if err != nil {
		return nil, err
	}
	if cfg.SNI == "" || net.ParseIP(cfg.SNI) != nil {
		return nil, errors.New("native REALITY requires an explicit DNS server name")
	}
	port, err := strconv.ParseUint(cfg.ServerPort, 10, 16)
	if err != nil || port == 0 {
		return nil, errors.New("invalid REALITY server port")
	}
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	raw, err := createClientDialer(cfg, 5*time.Second).DialContext(ctx, "tcp", net.JoinHostPort(cfg.ServerHost, cfg.ServerPort))
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		setOptimalTCPConn(tcp)
	}
	_ = raw.SetDeadline(time.Now().Add(12 * time.Second))
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	conn, err := xreality.UClient(raw, &xreality.Config{
		ServerName: cfg.SNI, PublicKey: key, ShortId: id[:], Fingerprint: fingerprint,
		SpiderX: "/", SpiderY: make([]int64, 10),
	}, ctx, xnet.TCPDestination(xnet.ParseAddress(cfg.ServerHost), xnet.Port(port)))
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("native REALITY handshake: %w", err)
	}
	if !stop() {
		conn.Close()
		return nil, ctx.Err()
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return &nativeRealityConn{conn}, nil
}

type NativeRealityServerConfig struct {
	Target           string
	ServerNames      []string
	PrivateKey       string
	ShortIDs         []string
	HandshakeTimeout time.Duration
}

// NewNativeRealityListener performs bounded target initialization, then serves
// authenticated TLS connections with bounded concurrent handshakes. Unknown
// clients are handled by upstream's real target fallback, never our fake flight.
func NewNativeRealityListener(ctx context.Context, inner net.Listener, cfg NativeRealityServerConfig) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key, err := DecodeRealityKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if _, _, err := net.SplitHostPort(cfg.Target); err != nil {
		return nil, fmt.Errorf("invalid REALITY target: %w", err)
	}
	if len(cfg.ServerNames) == 0 || len(cfg.ShortIDs) == 0 {
		return nil, errors.New("native REALITY needs server names and nonempty short IDs")
	}
	uc := &upstream.Config{
		Type: "tcp", Dest: cfg.Target, PrivateKey: priv, MaxTimeDiff: 2 * time.Minute,
		// Match Xray's GetREALITYConfig: the mirrored ticket records are handled
		// by REALITY itself, not by the Go server's normal ticket generator.
		SessionTicketsDisabled: true,
		ServerNames:            make(map[string]bool), ShortIds: make(map[[8]byte]bool),
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}
	for _, sni := range cfg.ServerNames {
		if strings.TrimSpace(sni) == "" || net.ParseIP(sni) != nil {
			return nil, errors.New("invalid REALITY server name")
		}
		uc.ServerNames[sni] = true
	}
	for _, value := range cfg.ShortIDs {
		id, err := DecodeRealityShortID(value)
		if err != nil {
			return nil, err
		}
		uc.ShortIds[id] = true
	}
	// Upstream's Server waits on these caches. Initialize before declaring the
	// listener ready, so the first client does not inherit a five-second poll.
	upstream.DetectPostHandshakeRecordsLens(uc)
	initCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		ready := true
		for sni := range uc.ServerNames {
			for alpn := range 3 {
				value, ok := upstream.GlobalPostHandshakeRecordsLens.Load(cfg.Target + " " + sni + " " + strconv.Itoa(alpn))
				if _, complete := value.([]int); !ok || !complete {
					ready = false
				}
			}
		}
		if ready {
			break
		}
		select {
		case <-initCtx.Done():
			return nil, fmt.Errorf("REALITY target initialization: %w", initCtx.Err())
		case <-tick.C:
		}
	}
	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	lctx, lcancel := context.WithCancel(ctx)
	l := &nativeRealityListener{Listener: inner, config: uc, timeout: timeout, ctx: lctx, cancel: lcancel,
		accepted: make(chan net.Conn), slots: make(chan struct{}, 128), pending: make(map[net.Conn]struct{}), stopped: make(chan struct{})}
	go l.run()
	go func() { <-lctx.Done(); _ = l.Close() }()
	return l, nil
}

type nativeRealityListener struct {
	net.Listener
	config   *upstream.Config
	timeout  time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	accepted chan net.Conn
	slots    chan struct{}
	mu       sync.Mutex
	pending  map[net.Conn]struct{}
	stopped  chan struct{}
	err      error
	once     sync.Once
}

func (l *nativeRealityListener) run() {
	defer close(l.stopped)
	defer l.cancel()
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			l.mu.Lock()
			l.err = err
			l.mu.Unlock()
			return
		}
		select {
		case l.slots <- struct{}{}:
		case <-l.ctx.Done():
			raw.Close()
			return
		}
		l.mu.Lock()
		if l.ctx.Err() != nil {
			l.mu.Unlock()
			<-l.slots
			raw.Close()
			return
		}
		l.pending[raw] = struct{}{}
		l.mu.Unlock()
		go l.handshake(raw)
	}
}

func (l *nativeRealityListener) handshake(raw net.Conn) {
	defer func() { <-l.slots; l.mu.Lock(); delete(l.pending, raw); l.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(l.timeout))
	conn, err := upstream.Server(l.ctx, raw, l.config)
	if err != nil {
		raw.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	select {
	case l.accepted <- &nativeRealityConn{conn}:
	case <-l.ctx.Done():
		conn.Close()
	}
}

func (l *nativeRealityListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.stopped:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err != nil {
			return nil, l.err
		}
		return nil, net.ErrClosed
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *nativeRealityListener) Close() error {
	var err error
	l.once.Do(func() {
		l.cancel()
		err = l.Listener.Close()
		l.mu.Lock()
		defer l.mu.Unlock()
		for conn := range l.pending {
			conn.Close()
		}
	})
	return err
}
