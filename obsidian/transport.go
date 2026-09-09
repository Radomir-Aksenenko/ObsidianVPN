package obsidian

// ── TLS Transport with uTLS + REALITY-mode ────────────────────────────────────
//
// Два режима:
//
// 1. Normal mode (VerifyCert=true/false):
//    Обычный uTLS Chrome 120 fingerprint → TLS к серверу.
//
// 2. REALITY mode (вдохновлён xray REALITY):
//    Сервер при получении НЕ-Obsidian соединения форвардит трафик на реальный
//    бэкенд (например microsoft.com:443) и проксирует ответ.
//    Клиент который знает ключ — попадает в VPN.
//    DPI и активное зондирование видят реальный сайт.
//
//    Как это работает:
//    - Клиент подключается, делает TLS handshake с SNI = реальный домен
//    - Сервер смотрит первые байты после TLS: если это HTTP/2 preface → Obsidian
//    - Если нет → форвардит соединение на реальный бэкенд (transparent proxy)
//    - Для ТСПУ сервер неотличим от настоящего microsoft.com

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"net"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

// ── SNI Pool ──────────────────────────────────────────────────────────────────

var DefaultSNIPool = []string{
	"www.microsoft.com",
	"cdn.cloudflare.com",
	"ajax.googleapis.com",
	"static.cloudflareinsights.com",
	"fonts.gstatic.com",
	"update.googleapis.com",
	"clients1.google.com",
}

func PickSNI(pool []string) string {
	if len(pool) == 0 {
		pool = DefaultSNIPool
	}
	return pool[rand.IntN(len(pool))]
}

// ── HTTP/2 Preface & Framing ──────────────────────────────────────────────────

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
var http2SettingsFrame = []byte{
	0x00, 0x00, 0x00, // Length: 0
	0x04,                   // Type: SETTINGS
	0x00,                   // Flags: None
	0x00, 0x00, 0x00, 0x00, // Stream ID: 0
}

func SendHTTP2Preface(conn net.Conn) error {
	full := make([]byte, len(http2Preface)+len(http2SettingsFrame))
	copy(full[:len(http2Preface)], http2Preface)
	copy(full[len(http2Preface):], http2SettingsFrame)
	_, err := conn.Write(full)
	return err
}

func RecvHTTP2Preface(conn net.Conn) error {
	buf := make([]byte, len(http2Preface))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if !ConstantTimeEqual(buf, http2Preface) {
		return errors.New("expected HTTP/2 preface not found")
	}
	return nil
}

// ── Self-Signed Certificate Generation ────────────────────────────────────────

// GenerateSelfSignedCertificate creates an in-memory ECDSA P-256 TLS certificate with Subject Alternative Names (SANs).
func GenerateSelfSignedCertificate(hosts ...string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate ecdsa key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := crand.Int(crand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial number: %w", err)
	}

	cn := "localhost"
	if len(hosts) > 0 && hosts[0] != "" && net.ParseIP(hosts[0]) == nil {
		cn = hosts[0]
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"localhost"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	// Always include loopback
	template.IPAddresses = append(template.IPAddresses, net.IPv4(127, 0, 0, 1), net.IPv6loopback)
	template.DNSNames = append(template.DNSNames, "localhost")

	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create x509 certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

// ── uTLS Client ───────────────────────────────────────────────────────────────

// SocketProtector is called with a raw socket file descriptor before the socket connects.
// This is essential on Android (VpnService.protect) and other environments to prevent routing loops.
type SocketProtector func(fd int) error

type ClientTransportConfig struct {
	ServerHost      string
	ServerPort      string
	SNI             string
	SNIPool         []string
	VerifyCert      bool
	ServerPubPin    []byte // Optional SHA-256 pin of server certificate DER bytes
	Fingerprint     *utls.ClientHelloID
	RealityEnabled  bool
	RealityAuthKey  []byte // Pre-shared authentication key for REALITY SessionID HMAC
	SocketProtector SocketProtector
	Dialer          *net.Dialer
}

func createClientDialer(cfg ClientTransportConfig, timeout time.Duration) *net.Dialer {
	if cfg.Dialer != nil {
		return cfg.Dialer
	}
	d := &net.Dialer{
		Timeout: timeout,
	}
	if cfg.SocketProtector != nil {
		d.Control = func(network, address string, c syscall.RawConn) error {
			var protectErr error
			err := c.Control(func(fd uintptr) {
				protectErr = cfg.SocketProtector(int(fd))
			})
			if err != nil {
				return err
			}
			return protectErr
		}
	}
	return d
}

// BuildTLSClientHelloRecord builds a TLS 1.3 ClientHello record with modern uTLS fingerprinting
// and injects the specified SessionID into the legacy_session_id vector.
func BuildTLSClientHelloRecord(sni string, sessionID []byte, fp *utls.ClientHelloID) ([]byte, error) {
	if fp == nil {
		fp = &utls.HelloChrome_Auto
	}
	tlsCfg := &utls.Config{
		ServerName: sni,
	}

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()

	uConn := utls.UClient(p1, tlsCfg, *fp)
	if err := uConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("build utls handshake state: %w", err)
	}

	if len(sessionID) > 0 {
		uConn.HandshakeState.Hello.SessionId = make([]byte, len(sessionID))
		copy(uConn.HandshakeState.Hello.SessionId, sessionID)
	}

	if err := uConn.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("marshal client hello: %w", err)
	}

	rawHello := uConn.HandshakeState.Hello.Raw
	if len(rawHello) == 0 {
		var err error
		rawHello, err = uConn.HandshakeState.Hello.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshal hello: %w", err)
		}
	}

	// Wrap in TLS Record: ContentType(1B, 0x16) || Version(2B, 0x0301) || Length(2B) || Payload
	record := make([]byte, 5+len(rawHello))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(rawHello)))
	copy(record[5:], rawHello)
	return record, nil
}

// DialObsidianREALITY establishes a REALITY-Plus / ShadowTLS v3 masked connection.
// It generates a steganographic SessionID auth token, sends an authentic uTLS ClientHello,
// and returns the underlying net.Conn ready for Obsidian's post-quantum handshake.
func DialObsidianREALITY(cfg ClientTransportConfig) (net.Conn, error) {
	sni := cfg.SNI
	if sni == "" {
		if net.ParseIP(cfg.ServerHost) == nil && cfg.ServerHost != "" {
			sni = cfg.ServerHost
		} else if len(cfg.SNIPool) > 0 {
			sni = PickSNI(cfg.SNIPool)
		} else {
			sni = PickSNI(DefaultSNIPool)
		}
	}

	sessionID, err := GenerateSessionID(cfg.RealityAuthKey, sni)
	if err != nil {
		return nil, fmt.Errorf("generate reality session id: %w", err)
	}

	addr := net.JoinHostPort(cfg.ServerHost, cfg.ServerPort)
	dialer := createClientDialer(cfg, 5*time.Second)
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		setOptimalTCPConn(tc)
	}

	clientHelloRecord, err := BuildTLSClientHelloRecord(sni, sessionID[:], cfg.Fingerprint)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("build client hello record: %w", err)
	}

	if _, err := rawConn.Write(clientHelloRecord); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("send reality client hello: %w", err)
	}

	// Complete legitimate TLS 1.3 handshake state machine by reading ServerHello
	_ = rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respHeader := make([]byte, 5)
	if _, err := io.ReadFull(rawConn, respHeader); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("read reality server hello record header: %w", err)
	}
	if respHeader[0] != 0x16 && respHeader[0] != 0x14 {
		rawConn.Close()
		return nil, fmt.Errorf("unexpected TLS record content type: 0x%02x", respHeader[0])
	}
	recordLen := int(binary.BigEndian.Uint16(respHeader[3:5]))
	if recordLen > 16384 {
		rawConn.Close()
		return nil, fmt.Errorf("server hello record too large: %d", recordLen)
	}
	respBody := make([]byte, recordLen)
	if _, err := io.ReadFull(rawConn, respBody); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("read reality server hello body: %w", err)
	}
	_ = rawConn.SetReadDeadline(time.Time{})

	return rawConn, nil
}

func setOptimalTCPConn(tc *net.TCPConn) {
	tc.SetNoDelay(true)
	sizes := []int{2 * 1024 * 1024, 1024 * 1024, 512 * 1024}
	for _, sz := range sizes {
		if err := tc.SetReadBuffer(sz); err == nil {
			break
		}
	}
	for _, sz := range sizes {
		if err := tc.SetWriteBuffer(sz); err == nil {
			break
		}
	}
}

// DialObsidian открывает uTLS соединение с современным TLS-отпечатком.
func DialObsidian(cfg ClientTransportConfig) (net.Conn, error) {
	if cfg.RealityEnabled {
		return DialObsidianREALITY(cfg)
	}
	sni := cfg.SNI
	if sni == "" {
		if net.ParseIP(cfg.ServerHost) == nil && cfg.ServerHost != "" {
			sni = cfg.ServerHost
		} else if len(cfg.SNIPool) > 0 {
			sni = PickSNI(cfg.SNIPool)
		} else {
			sni = cfg.ServerHost
		}
	}

	addr := net.JoinHostPort(cfg.ServerHost, cfg.ServerPort)
	dialer := createClientDialer(cfg, 5*time.Second)
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := rawConn.(*net.TCPConn); ok {
		setOptimalTCPConn(tc)
	}

	tlsCfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: len(cfg.ServerPubPin) > 0 || !cfg.VerifyCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(cfg.ServerPubPin) > 0 {
				if len(rawCerts) == 0 {
					return errors.New("no peer certificates presented")
				}
				certHash := sha256.Sum256(rawCerts[0])
				if !ConstantTimeEqual(certHash[:], cfg.ServerPubPin) {
					return errors.New("server certificate pin mismatch")
				}
			}
			return nil
		},
	}

	fp := cfg.Fingerprint
	if fp == nil {
		fp = &utls.HelloChrome_120
	}

	uConn := utls.UClient(rawConn, tlsCfg, *fp)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	if err := SendHTTP2Preface(uConn); err != nil {
		uConn.Close()
		return nil, err
	}

	return uConn, nil
}

// ── Standard TLS Server ───────────────────────────────────────────────────────

type ServerTransportConfig struct {
	Host     string
	Port     string
	CertFile string
	KeyFile  string
}

func ListenObsidian(cfg ServerTransportConfig) (net.Listener, error) {
	var cert tls.Certificate
	var err error
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, err
		}
	} else {
		cert, err = GenerateSelfSignedCertificate(cfg.Host, "localhost", "127.0.0.1")
		if err != nil {
			return nil, err
		}
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	addr := net.JoinHostPort(cfg.Host, cfg.Port)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(&noDelayListener{tcpListener}, tlsCfg), nil
}

// ListenObsidianREALITY starts a raw TCP listener on host:port configured with REALITY-Plus / ShadowTLS v3 demuxing.
func ListenObsidianREALITY(host, port string, cfg RealityDemuxConfig) (net.Listener, error) {
	addr := net.JoinHostPort(host, port)
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return NewRealityDemuxer(cfg, &noDelayListener{tcpListener}), nil
}

// ── REALITY mode ──────────────────────────────────────────────────────────────

// RealityConfig — конфиг REALITY-подобного режима.
type RealityConfig struct {
	// BackendAddr — реальный сервер куда форвардить не-VPN соединения.
	// Например: "www.microsoft.com:443"
	BackendAddr string
	// BackendTLSName — SNI для подключения к бэкенду
	BackendTLSName string
	// Timeout на подключение к бэкенду
	DialTimeout time.Duration
}

// RealityHandler — обёртка над обычным handler.
// Читает первые N байт после TLS: если HTTP/2 preface → вызывает obsidianHandler,
// иначе → transparent proxy на BackendAddr.
//
// Использование на сервере:
//
//	listener := ListenObsidian(cfg)
//	reality := NewRealityHandler(realityCfg, myObsidianHandler)
//	for {
//	    conn, _ := listener.Accept()
//	    go reality.Handle(conn)
//	}
type RealityHandler struct {
	cfg            RealityConfig
	obsidianHandle func(conn net.Conn, firstBytes []byte)
}

func NewRealityHandler(cfg RealityConfig, obsidianHandle func(conn net.Conn, firstBytes []byte)) *RealityHandler {
	return &RealityHandler{cfg: cfg, obsidianHandle: obsidianHandle}
}

// Handle определяет тип соединения и роутит его.
func (r *RealityHandler) Handle(conn net.Conn) {
	// Читаем ровно len(http2Preface) байт с таймаутом
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(http2Preface))
	n, err := io.ReadFull(conn, buf)
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		conn.Close()
		return
	}

	if ConstantTimeEqual(buf[:n], http2Preface) {
		// Это Obsidian клиент — передаём управление
		r.obsidianHandle(conn, buf[:n])
		return
	}

	// Не Obsidian — прозрачный прокси на бэкенд
	r.forwardToBackend(conn, buf[:n])
}

func (r *RealityHandler) forwardToBackend(clientConn net.Conn, firstBytes []byte) {
	defer clientConn.Close()

	if r.cfg.BackendAddr == "" {
		return
	}

	timeout := r.cfg.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	var backendConn net.Conn
	var err error

	if r.cfg.BackendTLSName != "" {
		// TLS к бэкенду (форвард на реальный HTTPS сервер)
		dialer := &tls.Dialer{
			Config: &tls.Config{
				ServerName: r.cfg.BackendTLSName,
				MinVersion: tls.VersionTLS12,
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		backendConn, err = dialer.DialContext(ctx, "tcp", r.cfg.BackendAddr)
	} else {
		backendConn, err = net.DialTimeout("tcp", r.cfg.BackendAddr, timeout)
	}
	if err != nil {
		return
	}
	defer backendConn.Close()

	// Отправляем уже прочитанные байты бэкенду
	if _, err := backendConn.Write(firstBytes); err != nil {
		return
	}

	// Двунаправленный прокси
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(backendConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, backendConn)
		done <- struct{}{}
	}()
	<-done
}

// ── Plain TCP (для локального тестирования без сертификатов) ─────────────────

// ListenTCP открывает обычный TCP listener (без TLS).
// Использовать только для локального тестирования.
// noDelayListener sets TCP_NODELAY on every accepted connection.
type noDelayListener struct{ net.Listener }

func (l *noDelayListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		setOptimalTCPConn(tc)
	}
	return conn, nil
}

func ListenTCP(host, port string) (net.Listener, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return &noDelayListener{l}, nil
}

// DialTCP подключается по TCP без TLS.
func DialTCP(host, port string) (net.Conn, error) {
	return DialTCPTimeout(host, port, 0)
}

func DialTCPTimeoutWithConfig(cfg ClientTransportConfig, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(cfg.ServerHost, cfg.ServerPort)
	dialer := createClientDialer(cfg, timeout)
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		setOptimalTCPConn(tc)
	}
	// HTTP/2 preface всё равно отправляем (часть протокола)
	if err := SendHTTP2Preface(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func DialTCPTimeout(host, port string, timeout time.Duration) (net.Conn, error) {
	return DialTCPTimeoutWithConfig(ClientTransportConfig{ServerHost: host, ServerPort: port}, timeout)
}
