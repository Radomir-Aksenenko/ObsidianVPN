package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"obsidian/obsidian"
)

type Config struct {
	ProtocolVersion       int      `json:"protocol_version"`
	Host                  string   `json:"host"`
	Port                  string   `json:"port"`
	NoTLS                 bool     `json:"no_tls"`
	CertFile              string   `json:"cert_file"`
	KeyFile               string   `json:"key_file"`
	ServerPrivateKey      string   `json:"server_private_key"`
	ServerPublicKey       string   `json:"server_public_key"`
	AllowedClients        []string `json:"allowed_clients"`
	RevokedClients        []string `json:"revoked_clients"`
	RevocationFile        string   `json:"revocation_file"`
	TunInterface          string   `json:"tun_interface"`
	TunAddress            string   `json:"tun_address"`
	OutInterface          string   `json:"out_interface"`
	MTU                   int      `json:"mtu"`
	DNSUpstream           string   `json:"dns_upstream"`
	DNSListen             string   `json:"dns_listen"`
	DisableDNSProxy       bool     `json:"disable_dns_proxy"`
	NoiseMinSec           float64  `json:"noise_min_sec"`
	NoiseMaxSec           float64  `json:"noise_max_sec"`
	KeepaliveSec          float64  `json:"keepalive_sec"`
	Jitter                string   `json:"jitter"`
	Profile               string   `json:"profile"`
	MaxHandshakes         int      `json:"max_concurrent_handshakes"`
	HandshakeRatePerIP    int      `json:"handshake_rate_per_ip"`
	HandshakeBurstPerIP   int      `json:"handshake_burst_per_ip"`
	RealityTarget         string   `json:"reality_target,omitempty"`
	RealityServerNames    []string `json:"reality_server_names,omitempty"`
	RealityAuthKey        string   `json:"reality_auth_key,omitempty"`
	RealityBackend        string   `json:"reality_backend,omitempty"`
	RealityBackendSNI     string   `json:"reality_backend_sni,omitempty"`
	JunkCount             int      `json:"junk_count"`
	JunkMin               int      `json:"junk_min"`
	JunkMax               int      `json:"junk_max"`
	Signatures            []string `json:"signatures"`
	UDPPort               string   `json:"udp_port"`
	EnableUDPData         bool     `json:"enable_udp_data"`
	PortPool              []int    `json:"port_pool,omitempty"`
	EnableCookieChallenge bool     `json:"enable_cookie_challenge,omitempty"`
	CookieSecret          string   `json:"cookie_secret,omitempty"`
	UDPSocketBufferMB     int      `json:"udp_socket_buffer_mb"`
	MaxTrailer            int      `json:"max_trailer,omitempty"`
	UseBucketPadding      bool     `json:"use_bucket_padding,omitempty"`
	BucketMTU             int      `json:"bucket_mtu,omitempty"`
	EnableIPv6            bool     `json:"enable_ipv6,omitempty"`
}

var (
	rateLimiter *obsidian.HandshakeRateLimiter
	// Global TUN — created once at startup, shared by all clients
	globalTUN io.ReadWriteCloser
	tunRoutes *tunRouter
	// UDP data mux — all clients share one UDP socket
	udpMux             *obsidian.UDPMux
	ipLimiter          *obsidian.IPRateLimiter
	replayCache        = newHandshakeReplayCache(2 * time.Minute)
	serverCookieSecret [32]byte
)

const (
	defaultUDPSocketBufferMB = 16
	minUDPSocketBufferMB     = 4
	maxUDPSocketBufferMB     = 64
)

func udpSocketBufferBytes(cfg Config) int {
	mb := cfg.UDPSocketBufferMB
	if mb <= 0 {
		mb = defaultUDPSocketBufferMB
	}
	if mb < minUDPSocketBufferMB {
		mb = minUDPSocketBufferMB
	}
	if mb > maxUDPSocketBufferMB {
		mb = maxUDPSocketBufferMB
	}
	return mb * 1024 * 1024
}

func main() {
	configPath := flag.String("config", "", "Path to server.json")
	genKeys := flag.Bool("gen-keys", false, "Generate server keypair and exit")
	flag.Parse()

	if *genKeys {
		kp, err := obsidian.GenerateKeypair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("server_private_key: %s\n", hex.EncodeToString(kp.Private[:]))
		fmt.Printf("server_public_key:  %s\n", hex.EncodeToString(kp.Public[:]))
		return
	}

	if *configPath == "" {
		log.Fatal("--config required")
	}

	f, err := os.Open(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		log.Fatal(err)
	}
	f.Close()

	if cfg.ProtocolVersion != 0 && cfg.ProtocolVersion != obsidian.ProtocolVersion {
		log.Fatalf("unsupported protocol_version: %d (server supports %d)", cfg.ProtocolVersion, obsidian.ProtocolVersion)
	}

	var serverPriv, serverPub [obsidian.KeySize]byte
	privBytes, err := hex.DecodeString(cfg.ServerPrivateKey)
	if err != nil || len(privBytes) != obsidian.KeySize {
		log.Fatal("invalid server_private_key")
	}
	pubBytes, err := hex.DecodeString(cfg.ServerPublicKey)
	if err != nil || len(pubBytes) != obsidian.KeySize {
		log.Fatal("invalid server_public_key")
	}
	copy(serverPriv[:], privBytes)
	copy(serverPub[:], pubBytes)

	var allowedClients [][obsidian.KeySize]byte
	if cfg.AllowedClients != nil {
		for _, ks := range cfg.AllowedClients {
			b, err := hex.DecodeString(ks)
			if err != nil || len(b) != obsidian.KeySize {
				log.Fatalf("invalid allowed_client key: %s", ks)
			}
			var k [obsidian.KeySize]byte
			copy(k[:], b)
			allowedClients = append(allowedClients, k)
		}
	}
	revocations, err := newRevocationStore(cfg.RevokedClients, cfg.RevocationFile)
	if cfg.CookieSecret != "" {
		b, err := hex.DecodeString(cfg.CookieSecret)
		if err == nil && len(b) == 32 {
			copy(serverCookieSecret[:], b)
		}
	}
	if serverCookieSecret == [32]byte{} {
		_, _ = io.ReadFull(rand.Reader, serverCookieSecret[:])
	}

	maxHS := cfg.MaxHandshakes
	if maxHS <= 0 {
		maxHS = 64
	}
	rateLimiter = obsidian.NewHandshakeRateLimiter(maxHS)

	ratePerIP := cfg.HandshakeRatePerIP
	if ratePerIP <= 0 {
		ratePerIP = 50
	}
	burstPerIP := cfg.HandshakeBurstPerIP
	if burstPerIP <= 0 {
		burstPerIP = 30
	}
	ipLimiter = obsidian.NewIPRateLimiter(ratePerIP, burstPerIP)

	tunnelCfg := obsidian.DefaultTunnelConfig()
	obfCfg := obsidian.DefaultObfuscationConfig()
	obsidian.ApplyProfile(cfg.Profile, &tunnelCfg, &obfCfg)
	tunnelCfg = makeTunnelConfig(cfg, tunnelCfg)
	obfCfg = makeObfConfig(cfg, obfCfg)

	// Create TUN once at startup
	globalTUN = openTUN(cfg)
	if globalTUN == nil {
		log.Printf("TUN unavailable — all clients will use echo mode")
	} else {
		tunRoutes = newTunRouter(globalTUN)
		go tunRoutes.run()
		if !cfg.DisableDNSProxy {
			if err := startDNSProxy(cfg); err != nil {
				log.Fatalf("DNS proxy unavailable: %v", err)
			}
		} else {
			log.Printf("WARNING: DNS proxy disabled; clients must not use tunnel DNS")
		}
	}

	// Start UDP data channel if configured
	if cfg.UDPPort != "" && cfg.EnableUDPData {
		udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Host, cfg.UDPPort))
		if err != nil {
			log.Fatal("resolve udp:", err)
		}
		udpConn, err := net.ListenUDP("udp4", udpAddr)
		if err != nil {
			log.Fatal("udp listen:", err)
		}
		udpBuf := udpSocketBufferBytes(cfg)
		if err := udpConn.SetReadBuffer(udpBuf); err != nil {
			log.Printf("udp read buffer %d bytes: %v", udpBuf, err)
		}
		if err := udpConn.SetWriteBuffer(udpBuf); err != nil {
			log.Printf("udp write buffer %d bytes: %v", udpBuf, err)
		}
		log.Printf("UDP socket buffers requested: read=%d MiB write=%d MiB", udpBuf/(1024*1024), udpBuf/(1024*1024))
		udpMux = obsidian.NewUDPMux(udpConn)

		// Register additional ports from PortPool for cryptographic port hopping
		for _, extraPort := range cfg.PortPool {
			if fmt.Sprintf("%d", extraPort) == cfg.UDPPort {
				continue
			}
			extraAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", extraPort)))
			if err != nil {
				log.Printf("resolve extra udp port %d: %v", extraPort, err)
				continue
			}
			extraConn, err := net.ListenUDP("udp4", extraAddr)
			if err != nil {
				log.Printf("listen extra udp port %d: %v", extraPort, err)
				continue
			}
			_ = extraConn.SetReadBuffer(udpBuf)
			_ = extraConn.SetWriteBuffer(udpBuf)
			udpMux.AddListener(extraConn)
			log.Printf("UDP data channel extra port listening on %s:%d", cfg.Host, extraPort)
		}

		go udpMux.Run()
		log.Printf("UDP data channel listening on %s:%s (port pool size: %d)", cfg.Host, cfg.UDPPort, len(cfg.PortPool))
	}

	realityTarget := cfg.RealityTarget
	if realityTarget == "" {
		realityTarget = cfg.RealityBackend
	}

	var realityServerNames []string
	if len(cfg.RealityServerNames) > 0 {
		realityServerNames = cfg.RealityServerNames
	} else if cfg.RealityBackendSNI != "" {
		realityServerNames = []string{cfg.RealityBackendSNI}
	}

	var realityAuthKey []byte
	if cfg.RealityAuthKey != "" {
		if b, err := hex.DecodeString(cfg.RealityAuthKey); err == nil && len(b) > 0 {
			realityAuthKey = b
		} else {
			realityAuthKey = []byte(cfg.RealityAuthKey)
		}
	} else {
		realityAuthKey = serverPub[:]
	}

	var listener net.Listener
	if realityTarget != "" {
		realityDemuxCfg := obsidian.RealityDemuxConfig{
			FallbackTarget:   realityTarget,
			ServerNames:      realityServerNames,
			AuthKey:          realityAuthKey,
			HandshakeTimeout: 5 * time.Second,
			DialTimeout:      10 * time.Second,
		}
		listener, err = obsidian.ListenObsidianREALITY(cfg.Host, cfg.Port, realityDemuxCfg)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ObsidianVPN server listening on %s:%s (REALITY-Plus active: fallback=%s, SNIs=%v)", cfg.Host, cfg.Port, realityTarget, realityServerNames)
	} else if cfg.NoTLS {
		log.Printf("WARNING: running without TLS (test mode only)")
		listener, err = obsidian.ListenTCP(cfg.Host, cfg.Port)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ObsidianVPN server listening on %s:%s (no_tls=%v)", cfg.Host, cfg.Port, cfg.NoTLS)
	} else {
		listener, err = obsidian.ListenObsidian(obsidian.ServerTransportConfig{
			Host:     cfg.Host,
			Port:     cfg.Port,
			CertFile: cfg.CertFile,
			KeyFile:  cfg.KeyFile,
		})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("ObsidianVPN server listening on %s:%s (no_tls=%v)", cfg.Host, cfg.Port, cfg.NoTLS)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("ObsidianVPN server shutdown initiated by OS signal")
		_ = listener.Close()
		if globalTUN != nil {
			_ = globalTUN.Close()
		}
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept error: %v", err)
			continue
		}
		go handleClient(conn, serverPriv, serverPub, allowedClients, revocations, tunnelCfg, obfCfg, cfg, realityTarget != "")
	}
}

func handleClient(conn net.Conn, priv, pub [obsidian.KeySize]byte,
	allowed [][obsidian.KeySize]byte, revocations *revocationStore, tunnelCfg obsidian.TunnelConfig,
	obfCfg obsidian.ObfuscationConfig, cfg Config, isReality bool) {

	defer conn.Close()
	log.Printf("new connection from %s", conn.RemoteAddr())

	remoteIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err == nil {
		if ip, parseErr := netip.ParseAddr(remoteIP); parseErr == nil && !ipLimiter.Allow(ip) {
			log.Printf("per-ip handshake rate limit exceeded, dropping %s", conn.RemoteAddr())
			return
		}
	}

	if !rateLimiter.Acquire() {
		log.Printf("rate limit exceeded, dropping %s", conn.RemoteAddr())
		return
	}
	defer rateLimiter.Release()

	if cfg.NoTLS {
		if err := obsidian.RecvHTTP2Preface(conn); err != nil {
			log.Printf("preface error from %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
	if !cfg.NoTLS && !isReality {
		if err := obsidian.RecvHTTP2Preface(conn); err != nil {
			log.Printf("preface error from %s: %v", conn.RemoteAddr(), err)
			return
		}
	}

	conn.SetReadDeadline(time.Now().Add(6 * time.Second))

	helloData, err := obsidian.ReadHelloFrame(conn, pub, 4096, 8192)
	if err != nil {
		log.Printf("client hello from %s: %v", conn.RemoteAddr(), err)
		return
	}
	conn.SetReadDeadline(time.Time{})

	if replayCache.Seen(helloData) {
		log.Printf("client hello replay from %s", conn.RemoteAddr())
		return
	}

	hs, err := obsidian.NewServerHandshakeWithConfig(priv, pub, allowed, obfCfg)
	if err != nil {
		log.Printf("handshake init: %v", err)
		return
	}
	serverHello, framer, err := hs.ProcessClientHello(helloData)
	if err != nil {
		log.Printf("handshake from %s: %v", conn.RemoteAddr(), err)
		return
	}
	if revocations.IsRevoked(hs.ClientStaticPub()) {
		log.Printf("revoked client rejected from %s", conn.RemoteAddr())
		return
	}

	serverHelloFrame, err := obsidian.BuildHelloFrame(pub, serverHello)
	if err != nil {
		log.Printf("server hello frame: %v", err)
		return
	}
	if _, err := conn.Write(serverHelloFrame); err != nil {
		return
	}

	sessionID := hex.EncodeToString(hs.SessionKeys.SessionID[:4])
	log.Printf("session %s: ready, peer=%s", sessionID, conn.RemoteAddr())

	tunnel := obsidian.NewTunnel(conn, framer, tunnelCfg)
	defer tunnel.Close()

	if globalTUN == nil || tunRoutes == nil {
		log.Printf("session %s: TUN unavailable, echo mode", sessionID)
		echoLoop(tunnel)
		return
	}

	if cfg.UDPPort != "" && cfg.EnableUDPData && udpMux != nil {
		// UDP data relay — TCP stays available as fallback until the UDP endpoint is learned.
		udpKeys := obsidian.DeriveUDPKeys(hs.SessionKeys, false)
		sess, err := udpMux.RegisterSession(udpKeys)
		if err != nil {
			log.Printf("session %s: udp register: %v", sessionID, err)
			return
		}
		defer sess.Close()
		sess.UseBucketPadding = tunnelCfg.UseBucketPadding
		if tunnelCfg.BucketMTU > 0 {
			sess.BucketMTU = tunnelCfg.BucketMTU
		}
		sess.MaxTrailer = tunnelCfg.MaxTrailer
		var lastUDPRecv atomic.Int64
		var lastTCPRecv atomic.Int64

		route := tunRoutes.registerSession(sessionID, func(packet []byte) error {
			lastT := lastTCPRecv.Load()
			lastU := lastUDPRecv.Load()
			preferTCP := false
			if lastT > lastU && lastT > 0 {
				now := time.Now().UnixNano()
				preferTCP = (now - lastU) > 2*time.Second.Nanoseconds()
			}

			if !preferTCP {
				err := sess.Send(packet)
				if err == nil {
					return nil
				}
				if !errors.Is(err, obsidian.ErrUDPClientAddrUnknown) {
					return err
				}
			}
			return tunnel.SendData(packet)
		})
		defer route.Close()
		udpDone := make(chan struct{})
		go func() {
			udpClientToTUN(sess, route, sessionID, &lastUDPRecv)
			close(udpDone)
		}()
		go tunnelToTUN(tunnel, route, sessionID, &lastTCPRecv)
		select {
		case <-tunnel.Done():
			log.Printf("session %s: control channel closed", sessionID)
		case <-udpDone:
		}
	} else {
		log.Printf("session %s: TCP relay started", sessionID)
		route := tunRoutes.registerSession(sessionID, tunnel.SendData)
		defer route.Close()
		tunnelToTUN(tunnel, route, sessionID)
	}
}

type handshakeReplayCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	seen map[[32]byte]time.Time
}

func newHandshakeReplayCache(ttl time.Duration) *handshakeReplayCache {
	return &handshakeReplayCache{ttl: ttl, seen: make(map[[32]byte]time.Time)}
}

func (c *handshakeReplayCache) Seen(hello []byte) bool {
	now := time.Now()
	sum := obsidian.HmacSHA256([]byte("obsidian_handshake_replay_cache_v2"), hello)
	var key [32]byte
	copy(key[:], sum)

	c.mu.Lock()
	defer c.mu.Unlock()
	if exp, ok := c.seen[key]; ok && now.Before(exp) {
		return true
	}
	if len(c.seen) > 4096 {
		for k, exp := range c.seen {
			if !now.Before(exp) {
				delete(c.seen, k)
			}
		}
	}
	c.seen[key] = now.Add(c.ttl)
	return false
}

func echoLoop(tunnel *obsidian.Tunnel) {
	buf := make([]byte, 2048)
	for {
		n, err := tunnel.RecvDataInto(nil, buf)
		if err != nil {
			return
		}
		if err := tunnel.SendData(buf[:n]); err != nil {
			return
		}
	}
}

func udpClientToTUN(sess *obsidian.UDPSession, tun io.Writer, sid string, lastRecv *atomic.Int64) {
	batch := make([]obsidian.UDPPacket, 32)
	for {
		n, err := sess.RecvBatch(batch)
		if err != nil {
			log.Printf("session %s: udp recv done: %v", sid, err)
			return
		}
		if lastRecv != nil {
			lastRecv.Store(time.Now().UnixNano())
		}
		for i := 0; i < n; i++ {
			data := batch[i].Payload
			batch[i] = obsidian.UDPPacket{}
			if len(data) == 0 {
				obsidian.PutPacket(data)
				continue
			}
			if shouldDropClientPacket(data) {
				log.Printf("session %s: dropping non-forwardable client packet: %s", sid, packetSummary(data))
				obsidian.PutPacket(data)
				continue
			}
			_, werr := tun.Write(data)
			obsidian.PutPacket(data) // return to pool
			if werr != nil {
				log.Printf("session %s: tun write dropped packet: %s: %v", sid, packetSummary(data), werr)
				continue
			}
		}
	}
}

func shouldDropClientPacket(packet []byte) bool {
	if len(packet) == 0 {
		return true
	}
	version := packet[0] >> 4
	if version == 4 {
		return looksLikeIPv4MulticastNameQuery(packet)
	}
	if version == 6 {
		if len(packet) < 40 {
			return true
		}
		// Drop IPv6 multicast queries (ff00::/8)
		if packet[24] == 0xff {
			return true
		}
		return false
	}
	return true
}

func looksLikeIPv4MulticastNameQuery(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 || packet[9] != 17 {
		return false
	}
	dst := packet[ihl+2:]
	if len(dst) < 2 {
		return false
	}
	dport := int(dst[0])<<8 | int(dst[1])
	if dport != 137 && dport != 5353 && dport != 5355 {
		return false
	}
	_, dstIP, ok := packetEndpoints(packet)
	if !ok {
		return false
	}
	d := dstIP.String()
	return strings.HasPrefix(d, "224.") || d == "239.255.255.250"
}

func tunnelToTUN(tunnel *obsidian.Tunnel, tun io.Writer, sid string, lastRecv ...*atomic.Int64) {
	buf := make([]byte, 2048)
	for {
		n, err := tunnel.RecvDataInto(nil, buf)
		if err != nil {
			log.Printf("session %s: tunnel recv error: %v", sid, err)
			return
		}
		if len(lastRecv) > 0 && lastRecv[0] != nil {
			lastRecv[0].Store(time.Now().UnixNano())
		}
		data := buf[:n]

		if shouldDropClientPacket(data) {
			log.Printf("session %s: dropping non-forwardable TCP client packet: %s", sid, packetSummary(data))
			continue
		}
		if _, err := tun.Write(data); err != nil {
			log.Printf("session %s: tun write dropped packet: %s: %v", sid, packetSummary(data), err)
			continue
		}
	}
}

func makeTunnelConfig(cfg Config, tc obsidian.TunnelConfig) obsidian.TunnelConfig {
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
	case "":
		// profile/default decides
	default:
		tc.Jitter = obsidian.JitterOff
	}
	return tc
}

func makeObfConfig(cfg Config, oc obsidian.ObfuscationConfig) obsidian.ObfuscationConfig {
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
			if err != nil {
				log.Fatalf("invalid signature %q: %v", s, err)
			}
			oc.Signatures = append(oc.Signatures, sig)
		}
	}
	return oc
}
