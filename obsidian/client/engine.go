package client

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"obsidian/obsidian"
)

// Status constants for client tunnel lifecycle.
const (
	StatusDisconnected = "disconnected"
	StatusConnecting   = "connecting"
	StatusConnected    = "connected"
	StatusReconnecting = "reconnecting"
	StatusError        = "error"
)

// SessionStats contains real-time metrics for an active or past tunnel session.
type SessionStats struct {
	Status             string `json:"status"`
	BytesSent          uint64 `json:"bytes_sent"`
	BytesReceived      uint64 `json:"bytes_received"`
	PacketsSent        uint64 `json:"packets_sent"`
	PacketsReceived    uint64 `json:"packets_received"`
	TxSpeedBps         uint64 `json:"tx_speed_bps"`
	RxSpeedBps         uint64 `json:"rx_speed_bps"`
	LastHandshakeUnix  int64  `json:"last_handshake_unix"`
	ActiveDataProtocol string `json:"active_data_protocol"` // "UDP" or "TCP"
}

// StatusCallback receives status and human-readable detail updates.
type StatusCallback func(status, detail string)

// StatsCallback receives periodic metrics updates.
type StatsCallback func(stats SessionStats)

// Option configures a client Session.
type Option func(*Session)

// WithSocketProtector injects a socket protector hook (critical for Android VpnService.protect).
func WithSocketProtector(p obsidian.SocketProtector) Option {
	return func(s *Session) {
		s.socketProtector = p
	}
}

// WithStatusCallback registers a callback for tunnel lifecycle state changes.
func WithStatusCallback(cb StatusCallback) Option {
	return func(s *Session) {
		s.statusCb = cb
	}
}

// WithStatsCallback registers a callback for real-time throughput metrics.
func WithStatsCallback(cb StatsCallback) Option {
	return func(s *Session) {
		s.statsCb = cb
	}
}

// WithDebug enables or disables diagnostic logging.
func WithDebug(debug bool) Option {
	return func(s *Session) {
		s.debug = debug
	}
}

// WithAutoReconnect controls automatic reconnect loop on connection drops.
func WithAutoReconnect(reconnect bool) Option {
	return func(s *Session) {
		s.autoReconnect = reconnect
	}
}

// Session manages the complete client-side tunnel lifecycle.
type Session struct {
	cfg             obsidian.ClientConfig
	serverPub       [obsidian.KeySize]byte
	clientStatic    *obsidian.Keypair
	obfCfg          obsidian.ObfuscationConfig
	tunnelCfg       obsidian.TunnelConfig
	socketProtector obsidian.SocketProtector
	statusCb        StatusCallback
	statsCb         StatsCallback
	debug           bool
	autoReconnect   bool

	statusMu sync.RWMutex
	status   string

	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	pktsSent      atomic.Uint64
	pktsReceived  atomic.Uint64
	txSpeed       atomic.Uint64
	rxSpeed       atomic.Uint64
	lastHandshake atomic.Int64
	activeProto   atomic.Pointer[string]

	stopCh chan struct{}
	doneCh chan struct{}
	stopOnce sync.Once
}

// NewSession creates an embeddable client Session from ClientConfig.
func NewSession(cfg *obsidian.ClientConfig, opts ...Option) (*Session, error) {
	if cfg == nil {
		return nil, errors.New("client config is nil")
	}

	pubBytes, err := hex.DecodeString(cfg.ServerPublicKey)
	if err != nil || len(pubBytes) != obsidian.KeySize {
		return nil, errors.New("invalid server_public_key (must be 64-char hex)")
	}
	var serverPub [obsidian.KeySize]byte
	copy(serverPub[:], pubBytes)

	var clientStatic *obsidian.Keypair
	if cfg.ClientPrivateKey == "" {
		kp, err := obsidian.GenerateKeypair()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral keypair: %w", err)
		}
		clientStatic = kp
		cfg.ClientPrivateKey = hex.EncodeToString(kp.Private[:])
	} else {
		privBytes, err := hex.DecodeString(cfg.ClientPrivateKey)
		if err != nil || len(privBytes) != obsidian.KeySize {
			return nil, errors.New("invalid client_private_key")
		}
		var clientPriv [obsidian.KeySize]byte
		copy(clientPriv[:], privBytes)
		clientStatic, err = obsidian.KeypairFromPrivate(clientPriv)
		if err != nil {
			return nil, fmt.Errorf("invalid client_private_key: %w", err)
		}
	}

	obfCfg := obsidian.DefaultObfuscationConfig()
	tunnelCfg := obsidian.DefaultTunnelConfig()
	obsidian.ApplyProfile(cfg.Profile, &tunnelCfg, &obfCfg)
	obfCfg = MakeObfConfig(*cfg, obfCfg)
	tunnelCfg = MakeTunnelConfig(*cfg, tunnelCfg)

	proto := "TCP"
	s := &Session{
		cfg:           *cfg,
		serverPub:     serverPub,
		clientStatic:  clientStatic,
		obfCfg:        obfCfg,
		tunnelCfg:     tunnelCfg,
		autoReconnect: true,
		status:        StatusDisconnected,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	s.activeProto.Store(&proto)

	for _, opt := range opts {
		opt(s)
	}

	return s, nil
}

// NewSessionFromURI parses an Obsidian URI (obsidian://..., vpn://..., OBSDN-...) and creates a Session.
func NewSessionFromURI(uri string, opts ...Option) (*Session, error) {
	cfg, err := obsidian.DecodeKey(uri)
	if err != nil {
		return nil, fmt.Errorf("decode URI/key: %w", err)
	}
	return NewSession(cfg, opts...)
}

// Start launches the tunnel synchronously on the provided TUN device.
func (s *Session) Start(dev io.ReadWriteCloser) error {
	defer close(s.doneCh)
	defer s.setStatus(StatusDisconnected, "Session stopped")

	// Start speed calculator and metrics reporter
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	go func() {
		var prevTx, prevRx uint64
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				curTx := s.bytesSent.Load()
				curRx := s.bytesReceived.Load()
				txDelta := curTx - prevTx
				rxDelta := curRx - prevRx
				prevTx = curTx
				prevRx = curRx
				s.txSpeed.Store(txDelta)
				s.rxSpeed.Store(rxDelta)

				if s.statsCb != nil {
					s.statsCb(s.GetStats())
				}
			}
		}
	}()

	attempt := 1
	for {
		select {
		case <-s.stopCh:
			return nil
		default:
		}

		if attempt == 1 {
			s.setStatus(StatusConnecting, fmt.Sprintf("Connecting to %s:%s", s.cfg.ServerHost, s.cfg.ServerPort))
		} else {
			s.setStatus(StatusReconnecting, fmt.Sprintf("[Attempt %d] Reconnecting to %s:%s", attempt, s.cfg.ServerHost, s.cfg.ServerPort))
		}

		err := s.runConnection(dev)
		if err != nil && s.isStopped() {
			return nil
		}

		if !s.autoReconnect {
			s.setStatus(StatusError, fmt.Sprintf("Connection ended: %v", err))
			return err
		}

		s.setStatus(StatusReconnecting, fmt.Sprintf("Connection dropped: %v — reconnecting in 3s", err))
		select {
		case <-s.stopCh:
			return nil
		case <-time.After(3 * time.Second):
			attempt++
		}
	}
}

// StartAsync runs the tunnel session in a background goroutine.
func (s *Session) StartAsync(dev io.ReadWriteCloser) {
	go func() {
		_ = s.Start(dev)
	}()
}

// Stop gracefully terminates the tunnel session.
func (s *Session) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
}

// Wait blocks until the session terminates.
func (s *Session) Wait() {
	<-s.doneCh
}

// Status returns current tunnel state.
func (s *Session) Status() string {
	s.statusMu.RLock()
	defer s.statusMu.RUnlock()
	return s.status
}

// GetStats returns real-time metrics snapshot.
func (s *Session) GetStats() SessionStats {
	proto := "TCP"
	if p := s.activeProto.Load(); p != nil {
		proto = *p
	}
	return SessionStats{
		Status:             s.Status(),
		BytesSent:          s.bytesSent.Load(),
		BytesReceived:      s.bytesReceived.Load(),
		PacketsSent:        s.pktsSent.Load(),
		PacketsReceived:    s.pktsReceived.Load(),
		TxSpeedBps:         s.txSpeed.Load(),
		RxSpeedBps:         s.rxSpeed.Load(),
		LastHandshakeUnix:  s.lastHandshake.Load(),
		ActiveDataProtocol: proto,
	}
}

func (s *Session) isStopped() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

func (s *Session) setStatus(st, detail string) {
	s.statusMu.Lock()
	s.status = st
	s.statusMu.Unlock()
	if s.statusCb != nil {
		s.statusCb(st, detail)
	}
	if s.debug {
		log.Printf("[ObsidianClient] status=%s detail=%s", st, detail)
	}
}

func (s *Session) runConnection(tun io.ReadWriteCloser) error {
	var (
		conn net.Conn
		err  error
	)

	isReality := s.cfg.RealityEnabled || s.cfg.RealityAuthKey != "" || s.cfg.RealitySNI != ""
	transportCfg := obsidian.ClientTransportConfig{
		ServerHost:      s.cfg.ServerHost,
		ServerPort:      s.cfg.ServerPort,
		SNI:             s.cfg.SNI,
		SNIPool:         s.cfg.SNIPool,
		VerifyCert:      s.cfg.VerifyTLS,
		Fingerprint:     parseFingerprint(s.cfg.Fingerprint),
		SocketProtector: s.socketProtector,
	}

	if isReality {
		var authKeyBytes []byte
		if s.cfg.RealityAuthKey != "" {
			if b, err := hex.DecodeString(s.cfg.RealityAuthKey); err == nil && len(b) > 0 {
				authKeyBytes = b
			} else {
				authKeyBytes = []byte(s.cfg.RealityAuthKey)
			}
		} else {
			authKeyBytes = s.serverPub[:]
		}

		sni := s.cfg.RealitySNI
		if sni == "" {
			sni = s.cfg.SNI
		}

		transportCfg.SNI = sni
		transportCfg.RealityEnabled = true
		transportCfg.RealityAuthKey = authKeyBytes
		conn, err = obsidian.DialObsidianREALITY(transportCfg)
	} else if s.cfg.NoTLS {
		conn, err = obsidian.DialTCPTimeoutWithConfig(transportCfg, 3*time.Second)
	} else {
		conn, err = obsidian.DialObsidian(transportCfg)
	}

	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	hs, err := obsidian.NewClientHandshakeWithStaticKey(s.serverPub, s.clientStatic, s.obfCfg)
	if err != nil {
		return fmt.Errorf("handshake init: %w", err)
	}

	if s.cfg.NoTLS {
		sigs, err := hs.BuildSignatureTrain()
		if err != nil {
			return fmt.Errorf("signature train: %w", err)
		}
		if len(sigs) > 0 {
			if _, err := conn.Write(sigs); err != nil {
				return fmt.Errorf("send signatures: %w", err)
			}
		}
	}

	if !isReality {
		junk, err := hs.BuildJunkTrain()
		if err != nil {
			return fmt.Errorf("junk train: %w", err)
		}
		if len(junk) > 0 {
			if _, err := conn.Write(junk); err != nil {
				return fmt.Errorf("send junk: %w", err)
			}
		}
	}

	hello, err := hs.BuildHello()
	if err != nil {
		return fmt.Errorf("build hello: %w", err)
	}
	helloFrame, err := obsidian.BuildHelloFrame(s.serverPub, hello)
	if err != nil {
		return fmt.Errorf("build hello frame: %w", err)
	}
	if _, err := conn.Write(helloFrame); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	srvHello, err := obsidian.ReadHelloFrame(conn, s.serverPub, 4096, 8192)
	if err != nil {
		return fmt.Errorf("read server hello: %w", err)
	}

	framer, err := hs.ProcessServerHello(srvHello)
	if err != nil {
		return fmt.Errorf("process server hello: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	s.lastHandshake.Store(time.Now().Unix())
	sessionID := hex.EncodeToString(hs.SessionKeys.SessionID[:4])
	s.setStatus(StatusConnected, fmt.Sprintf("Session %s active", sessionID))

	tunnel := obsidian.NewTunnel(conn, framer, s.tunnelCfg)
	defer tunnel.Close()

	// Handle UDP data channel if enabled
	if s.cfg.UDPPort != "" && s.cfg.EnableUDPData {
		udpKeys := obsidian.DeriveUDPKeys(hs.SessionKeys, true)
		udpRemote := net.JoinHostPort(s.cfg.ServerHost, s.cfg.UDPPort)
		udpConn, err := obsidian.DialProtectedUDP("udp4", udpRemote, s.socketProtector)
		if err != nil {
			return fmt.Errorf("dial udp: %w", err)
		}
		setOptimalUDPBuffers(udpConn)

		udpCh, err := obsidian.NewUDPChannel(udpConn, udpKeys)
		if err != nil {
			return fmt.Errorf("udp channel: %w", err)
		}
		defer udpCh.Close()
		udpCh.UseBucketPadding = s.tunnelCfg.UseBucketPadding
		if s.tunnelCfg.BucketMTU > 0 {
			udpCh.BucketMTU = s.tunnelCfg.BucketMTU
		}
		udpCh.MaxTrailer = s.tunnelCfg.MaxTrailer
		warmupUDPAddress(udpCh)

		udpProto := "UDP"
		tcpProto := "TCP"
		s.activeProto.Store(&udpProto)

		var (
			lastUDPRecvNano atomic.Int64
			udpActive       atomic.Bool
		)
		udpActive.Store(true)
		lastUDPRecvNano.Store(time.Now().UnixNano())

		// Port hopping
		if len(s.cfg.PortPool) > 0 {
			hopSec := s.cfg.PortHopIntervalSec
			if hopSec <= 0 {
				hopSec = 300
			}
			go func() {
				ticker := time.NewTicker(time.Duration(hopSec) * time.Second)
				defer ticker.Stop()
				var epoch uint64 = 1
				for {
					select {
					case <-ticker.C:
						nextPort, err := obsidian.DeriveHoppingPort(hs.SessionKeys.SessionID, epoch, s.cfg.PortPool)
						if err == nil {
							udpCh.SetRemotePort(nextPort)
							warmupUDPAddress(udpCh)
							epoch++
						}
					case <-tunnel.Done():
						return
					case <-s.stopCh:
						return
					}
				}
			}()
		}

		// Failover health monitor
		monitorDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(2 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					now := time.Now().UnixNano()
					lastRecv := lastUDPRecvNano.Load()
					if !udpActive.Load() {
						_ = udpCh.Send(nil)
						if (now - lastRecv) < 3*time.Second.Nanoseconds() {
							udpActive.Store(true)
							s.activeProto.Store(&udpProto)
						}
					}
				case <-tunnel.Done():
					return
				case <-monitorDone:
					return
				case <-s.stopCh:
					return
				}
			}
		}()

		errCh := make(chan error, 3)
		go func() { errCh <- s.copyTunToData(tun, udpCh, tunnel, &udpActive, &tcpProto) }()
		go func() { errCh <- s.copyUDPToTun(udpCh, tun, &lastUDPRecvNano) }()
		go func() { errCh <- s.copyTunnelToTun(tunnel, tun) }()

		select {
		case err := <-errCh:
			close(monitorDone)
			return err
		case <-tunnel.Done():
			close(monitorDone)
			return io.EOF
		case <-s.stopCh:
			close(monitorDone)
			return nil
		}
	}

	// TCP fallback / TCP-only mode
	tcpProto := "TCP"
	s.activeProto.Store(&tcpProto)
	errCh := make(chan error, 2)
	go func() { errCh <- s.copyTunToTunnel(tun, tunnel) }()
	go func() { errCh <- s.copyTunnelToTun(tunnel, tun) }()

	select {
	case err := <-errCh:
		return err
	case <-tunnel.Done():
		return io.EOF
	case <-s.stopCh:
		return nil
	}
}

func (s *Session) copyTunToData(tun io.Reader, ch *obsidian.UDPChannel, tunnel *obsidian.Tunnel, udpActive *atomic.Bool, tcpProto *string) error {
	buf := make([]byte, 2048)
	sendBuf := make([]byte, 2048)
	var udpFailCount atomic.Int32

	for {
		if s.isStopped() {
			return nil
		}
		n, err := tun.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		packet := buf[:n]
		s.pktsSent.Add(1)
		s.bytesSent.Add(uint64(n))

		if !s.cfg.EnableIPv6 && isIPv6Packet(packet) {
			continue
		}

		if udpActive.Load() {
			if err := ch.SendWithBuffer(packet, sendBuf); err != nil {
				if isTemporaryNetworkError(err) {
					continue
				}
				fails := udpFailCount.Add(1)
				if fails >= 5 {
					udpActive.Store(false)
					s.activeProto.Store(tcpProto)
				}
				if err := tunnel.SendData(packet); err != nil {
					return fmt.Errorf("tunnel send: %w", err)
				}
			} else {
				udpFailCount.Store(0)
			}
		} else {
			if err := tunnel.SendData(packet); err != nil {
				return fmt.Errorf("tunnel send: %w", err)
			}
		}
	}
}

func (s *Session) copyUDPToTun(ch *obsidian.UDPChannel, tun io.Writer, lastUDPRecvNano *atomic.Int64) error {
	buf := make([]byte, 2048)
	for {
		if s.isStopped() {
			return nil
		}
		n, err := ch.Recv(buf)
		if err != nil {
			return fmt.Errorf("udp recv: %w", err)
		}
		if lastUDPRecvNano != nil {
			lastUDPRecvNano.Store(time.Now().UnixNano())
		}
		s.pktsReceived.Add(1)
		s.bytesReceived.Add(uint64(n))

		if _, err := tun.Write(buf[:n]); err != nil {
			return fmt.Errorf("tun write: %w", err)
		}
	}
}

func (s *Session) copyTunToTunnel(tun io.Reader, tunnel *obsidian.Tunnel) error {
	buf := make([]byte, 2048)
	for {
		if s.isStopped() {
			return nil
		}
		n, err := tun.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		s.pktsSent.Add(1)
		s.bytesSent.Add(uint64(n))

		if err := tunnel.SendData(buf[:n]); err != nil {
			return fmt.Errorf("tunnel send: %w", err)
		}
	}
}

func (s *Session) copyTunnelToTun(tunnel *obsidian.Tunnel, tun io.Writer) error {
	buf := make([]byte, 2048)
	for {
		if s.isStopped() {
			return nil
		}
		n, err := tunnel.RecvDataInto(nil, buf)
		if err != nil {
			return fmt.Errorf("tunnel recv: %w", err)
		}
		s.pktsReceived.Add(1)
		s.bytesReceived.Add(uint64(n))

		if _, err := tun.Write(buf[:n]); err != nil {
			return fmt.Errorf("tun write: %w", err)
		}
	}
}

func parseFingerprint(name string) *utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "firefox", "firefox_auto":
		return &utls.HelloFirefox_Auto
	case "safari", "safari_auto":
		return &utls.HelloSafari_Auto
	case "edge", "edge_auto":
		return &utls.HelloEdge_Auto
	case "randomized", "random":
		return &utls.HelloRandomizedALPN
	default:
		return &utls.HelloChrome_Auto
	}
}

func warmupUDPAddress(ch *obsidian.UDPChannel) {
	for i := 0; i < 5; i++ {
		if err := ch.Send(nil); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func setOptimalUDPBuffers(conn *net.UDPConn) {
	sizes := []int{16 * 1024 * 1024, 8 * 1024 * 1024, 4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024}
	for _, sz := range sizes {
		if err := conn.SetReadBuffer(sz); err == nil {
			break
		}
	}
	for _, sz := range sizes {
		if err := conn.SetWriteBuffer(sz); err == nil {
			break
		}
	}
}

func isTemporaryNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "would block") || strings.Contains(s, "resource temporarily unavailable") || strings.Contains(s, "operation was canceled")
}

func isIPv6Packet(packet []byte) bool {
	return len(packet) > 0 && packet[0]>>4 == 6
}

// MakeTunnelConfig translates ClientConfig fields into TunnelConfig.
func MakeTunnelConfig(cfg obsidian.ClientConfig, tc obsidian.TunnelConfig) obsidian.TunnelConfig {
	if cfg.NoiseMinSec > 0 {
		tc.NoiseMinInterval = time.Duration(cfg.NoiseMinSec * float64(time.Second))
	}
	if cfg.NoiseMaxSec > 0 {
		tc.NoiseMaxInterval = time.Duration(cfg.NoiseMaxSec * float64(time.Second))
	}
	if cfg.KeepaliveSec > 0 {
		tc.KeepaliveInterval = time.Duration(cfg.KeepaliveSec * float64(time.Second))
	}
	if cfg.UseBucketPadding {
		tc.UseBucketPadding = true
	}
	if cfg.BucketMTU > 0 {
		tc.BucketMTU = cfg.BucketMTU
	}
	if cfg.MaxTrailer > 0 {
		tc.MaxTrailer = cfg.MaxTrailer
	}
	switch cfg.Jitter {
	case "off":
		tc.Jitter = obsidian.JitterOff
	case "light":
		tc.Jitter = obsidian.JitterLight
	case "medium":
		tc.Jitter = obsidian.JitterMedium
	case "heavy":
		tc.Jitter = obsidian.JitterHeavy
	default:
		tc.Jitter = obsidian.JitterOff
	}
	return tc
}

// MakeObfConfig translates ClientConfig fields into ObfuscationConfig.
func MakeObfConfig(cfg obsidian.ClientConfig, oc obsidian.ObfuscationConfig) obsidian.ObfuscationConfig {
	if cfg.JunkCount > 0 {
		oc.JunkCount = cfg.JunkCount
	}
	if cfg.JunkMin > 0 {
		oc.JunkMin = cfg.JunkMin
	}
	if cfg.JunkMax > 0 {
		oc.JunkMax = cfg.JunkMax
	}
	if cfg.MaxTrailer > 0 {
		oc.MaxTrailer = cfg.MaxTrailer
	}
	if len(cfg.Signatures) > 0 {
		oc.Signatures = nil
		for _, s := range cfg.Signatures {
			sig, err := obsidian.ParseCPS(s)
			if err == nil {
				oc.Signatures = append(oc.Signatures, sig)
			}
		}
	}
	return oc
}
