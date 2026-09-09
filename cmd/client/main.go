package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"obsidian/obsidian"
)

type Config = obsidian.ClientConfig

const udpSocketBufferSize = 64 * 1024 * 1024

var debugLogging bool

func main() {
	configPath := flag.String("config", "", "Path to client.json")
	uriFlag := flag.String("uri", "", "Obsidian URI (obsidian://..., vpn://...) or OBSDN- key to connect")
	toURIFlag := flag.Bool("to-uri", false, "Convert --config client.json into obsidian:// URI and exit")
	labelFlag := flag.String("label", "", "Optional label for generated URI (used with --to-uri)")
	clientKeyFlag := flag.String("client-key", "", "Optional client private key (hex, 64 chars)")
	genKeys := flag.Bool("gen-keys", false, "Generate client keypair and exit")
	debug := flag.Bool("debug", false, "Print detailed, non-secret connection diagnostics")
	flag.Parse()
	debugLogging = *debug

	if *genKeys {
		kp, err := obsidian.GenerateKeypair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("client_private_key: %s\n", hex.EncodeToString(kp.Private[:]))
		fmt.Printf("client_public_key:  %s\n", hex.EncodeToString(kp.Public[:]))
		return
	}

	var cfg Config

	if *toURIFlag {
		if *configPath == "" {
			log.Fatal("--config required when using --to-uri")
		}
		f, err := os.Open(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewDecoder(f).Decode(&cfg); err != nil {
			log.Fatal(err)
		}
		f.Close()
		uri := obsidian.EncodeURI(&cfg, *labelFlag)
		fmt.Println(uri)
		return
	}

	if *uriFlag != "" {
		parsed, err := obsidian.DecodeKey(*uriFlag)
		if err != nil {
			log.Fatalf("failed to decode URI/key: %v", err)
		}
		cfg = *parsed
		if *clientKeyFlag != "" {
			cfg.ClientPrivateKey = *clientKeyFlag
		}
	} else if *configPath != "" {
		f, err := os.Open(*configPath)
		if err != nil {
			log.Fatal(err)
		}
		if err := json.NewDecoder(f).Decode(&cfg); err != nil {
			log.Fatal(err)
		}
		f.Close()
	} else {
		log.Fatal("either --config or --uri is required")
	}

	if cfg.ProtocolVersion != 0 && cfg.ProtocolVersion != obsidian.ProtocolVersion {
		log.Fatalf("unsupported protocol_version: %d (client supports %d); press 'Починить сервер' in the app", cfg.ProtocolVersion, obsidian.ProtocolVersion)
	}

	pubBytes, err := hex.DecodeString(cfg.ServerPublicKey)
	if err != nil || len(pubBytes) != obsidian.KeySize {
		log.Fatal("invalid server_public_key")
	}
	var serverPub [obsidian.KeySize]byte
	copy(serverPub[:], pubBytes)

	var clientStatic *obsidian.Keypair
	if cfg.ClientPrivateKey == "" {
		kp, err := obsidian.GenerateKeypair()
		if err != nil {
			log.Fatalf("failed to generate ephemeral client keypair: %v", err)
		}
		clientStatic = kp
		cfg.ClientPrivateKey = hex.EncodeToString(kp.Private[:])
		log.Printf("no client key specified; generated ephemeral client public key: %s", hex.EncodeToString(clientStatic.Public[:]))
	} else {
		privBytes, err := hex.DecodeString(cfg.ClientPrivateKey)
		if err != nil || len(privBytes) != obsidian.KeySize {
			log.Fatal("invalid client_private_key")
		}
		var clientPriv [obsidian.KeySize]byte
		copy(clientPriv[:], privBytes)
		clientStatic, err = obsidian.KeypairFromPrivate(clientPriv)
		if err != nil {
			log.Fatalf("invalid client_private_key: %v", err)
		}
		log.Printf("client public key: %s", hex.EncodeToString(clientStatic.Public[:]))
	}
	debugf("config: server=%s:%s, no_tls=%v, profile=%q, udp_data=%v", cfg.ServerHost, cfg.ServerPort, cfg.NoTLS, cfg.Profile, cfg.EnableUDPData && cfg.UDPPort != "")
	debugf("config: server public key fingerprint=%s", hex.EncodeToString(serverPub[:8]))

	obfCfg := obsidian.DefaultObfuscationConfig()
	tunnelCfg := obsidian.DefaultTunnelConfig()
	obsidian.ApplyProfile(cfg.Profile, &tunnelCfg, &obfCfg)
	obfCfg = makeObfConfig(cfg, obfCfg)
	tunnelCfg = makeTunnelConfig(cfg, tunnelCfg)

	tun := openTUN(cfg)
	if tun == nil {
		log.Fatal("failed to open TUN interface")
	}
	defer tun.Close()
	log.Printf("TUN %s up (%s)", cfg.TunInterface, cfg.TunAddress)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Watch stdin for clean parent exit (e.g. from Tauri GUI when closing/disconnecting)
	shutdownCh := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for {
			_, err := os.Stdin.Read(buf)
			if err != nil {
				close(shutdownCh)
				return
			}
		}
	}()

	go func() {
		select {
		case <-sigCh:
			log.Println("client shutdown initiated by OS signal")
		case <-shutdownCh:
			log.Println("client shutdown initiated by parent process disconnect")
		}
		tun.Close()
		os.Exit(0)
	}()

	for attempt := 1; ; attempt++ {
		log.Printf("[attempt %d] connecting to %s:%s", attempt, cfg.ServerHost, cfg.ServerPort)
		err := runSession(cfg, serverPub, clientStatic, obfCfg, tunnelCfg, tun)
		log.Printf("session ended: %v — reconnecting in 3s", err)

		select {
		case <-sigCh:
			log.Println("client shutdown initiated by OS signal")
			tun.Close()
			return
		case <-shutdownCh:
			log.Println("client shutdown initiated by parent process disconnect")
			tun.Close()
			return
		case <-time.After(3 * time.Second):
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

func runSession(cfg Config, serverPub [obsidian.KeySize]byte, clientStatic *obsidian.Keypair, obfCfg obsidian.ObfuscationConfig, tunnelCfg obsidian.TunnelConfig, tun io.ReadWriter) error {
	var (
		conn net.Conn
		err  error
	)
	isReality := cfg.RealityEnabled || cfg.RealityAuthKey != "" || cfg.RealitySNI != ""
	if isReality {
		var authKeyBytes []byte
		if cfg.RealityAuthKey != "" {
			if b, err := hex.DecodeString(cfg.RealityAuthKey); err == nil && len(b) > 0 {
				authKeyBytes = b
			} else {
				authKeyBytes = []byte(cfg.RealityAuthKey)
			}
		} else {
			authKeyBytes = serverPub[:]
		}

		sni := cfg.RealitySNI
		if sni == "" {
			sni = cfg.SNI
		}

		fp := parseFingerprint(cfg.Fingerprint)
		debugf("transport: dialing via REALITY-Plus (SNI=%s)", sni)
		conn, err = obsidian.DialObsidianREALITY(obsidian.ClientTransportConfig{
			ServerHost:     cfg.ServerHost,
			ServerPort:     cfg.ServerPort,
			SNI:            sni,
			SNIPool:        cfg.SNIPool,
			RealityEnabled: true,
			RealityAuthKey: authKeyBytes,
			Fingerprint:    fp,
		})
	} else if cfg.NoTLS {
		debugf("transport: dialing raw TCP")
		conn, err = obsidian.DialTCPTimeout(cfg.ServerHost, cfg.ServerPort, 3*time.Second)
	} else {
		conn, err = obsidian.DialObsidian(obsidian.ClientTransportConfig{
			ServerHost:  cfg.ServerHost,
			ServerPort:  cfg.ServerPort,
			SNI:         cfg.SNI,
			SNIPool:     cfg.SNIPool,
			VerifyCert:  cfg.VerifyTLS,
			Fingerprint: parseFingerprint(cfg.Fingerprint),
		})
	}
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	debugf("transport: connected local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		log.Printf("set handshake deadline: %v", err)
	}

	hs, err := obsidian.NewClientHandshakeWithStaticKey(serverPub, clientStatic, obfCfg)
	if err != nil {
		return fmt.Errorf("handshake init: %w", err)
	}

	// 1. Signature train (only for raw TCP test mode if explicitly configured)
	if cfg.NoTLS {
		sigs, err := hs.BuildSignatureTrain()
		if err != nil {
			return fmt.Errorf("signature train: %w", err)
		}
		if len(sigs) > 0 {
			debugf("handshake: sending signature train (%d bytes)", len(sigs))
			if _, err := conn.Write(sigs); err != nil {
				return fmt.Errorf("send signatures: %w", err)
			}
		}
	}

	// 2. Junk train. Skip on REALITY: after a TLS ServerHello, extra
	// non-TLS bytes are a cheap DPI tell. ReadHelloFrame on the server
	// already scans past junk, so this stays compatible.
	if !isReality {
		junk, err := hs.BuildJunkTrain()
		if err != nil {
			return fmt.Errorf("junk train: %w", err)
		}
		if len(junk) > 0 {
			debugf("handshake: sending junk train (%d bytes)", len(junk))
			if _, err := conn.Write(junk); err != nil {
				return fmt.Errorf("send junk: %w", err)
			}
		}
	}

	// 3. ClientHello
	hello, err := hs.BuildHello()
	if err != nil {
		return fmt.Errorf("build hello: %w", err)
	}
	helloFrame, err := obsidian.BuildHelloFrame(serverPub, hello)
	if err != nil {
		return fmt.Errorf("build hello frame: %w", err)
	}
	debugf("handshake: sending authenticated ClientHello (%d bytes)", len(helloFrame))
	if _, err := conn.Write(helloFrame); err != nil {
		return fmt.Errorf("send hello: %w", err)
	}

	// 4. ServerHello
	debugf("handshake: waiting for ServerHello (deadline 6s)")
	srvHello, err := obsidian.ReadHelloFrame(conn, serverPub, 4096, 8192)
	if err != nil {
		return fmt.Errorf("read server hello frame: %w (server did not return a recognizable response; verify server_public_key, server logs, and traffic filtering)", err)
	}
	debugf("handshake: received ServerHello (%d bytes)", len(srvHello))

	framer, err := hs.ProcessServerHello(srvHello)
	if err != nil {
		return fmt.Errorf("process server hello: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})

	sessionID := hex.EncodeToString(hs.SessionKeys.SessionID[:4])
	log.Printf("session %s: ready", sessionID)

	tunnel := obsidian.NewTunnel(conn, framer, tunnelCfg)
	defer tunnel.Close()

	if cfg.UDPPort != "" && cfg.EnableUDPData {
		udpKeys := obsidian.DeriveUDPKeys(hs.SessionKeys, true)
		udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.ServerHost, cfg.UDPPort))
		if err != nil {
			return fmt.Errorf("resolve udp: %w", err)
		}
		udpConn, err := net.DialUDP("udp4", nil, udpAddr)
		if err != nil {
			return fmt.Errorf("dial udp: %w", err)
		}
		setOptimalUDPBuffers(udpConn)

		udpCh, err := obsidian.NewUDPChannel(udpConn, udpKeys)
		if err != nil {
			return fmt.Errorf("udp channel: %w", err)
		}
		defer udpCh.Close()
		udpCh.UseBucketPadding = tunnelCfg.UseBucketPadding
		if tunnelCfg.BucketMTU > 0 {
			udpCh.BucketMTU = tunnelCfg.BucketMTU
		}
		udpCh.MaxTrailer = tunnelCfg.MaxTrailer
		log.Printf("UDP data channel: %s:%s (bucket_padding=%v)", cfg.ServerHost, cfg.UDPPort, udpCh.UseBucketPadding)
		warmupUDPAddress(udpCh)

		if len(cfg.PortPool) > 0 {
			hopSec := cfg.PortHopIntervalSec
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
						nextPort, err := obsidian.DeriveHoppingPort(hs.SessionKeys.SessionID, epoch, cfg.PortPool)
						if err == nil {
							debugf("port hopping: switching destination to port %d (epoch %d)", nextPort, epoch)
							udpCh.SetRemotePort(nextPort)
							warmupUDPAddress(udpCh)
							epoch++
						}
					case <-tunnel.Done():
						return
					}
				}
			}()
		}

		var (
			lastUDPRecvNano atomic.Int64
			udpActive       atomic.Bool
		)
		udpActive.Store(true)
		nowNano := time.Now().UnixNano()
		lastUDPRecvNano.Store(nowNano)

		// Failover health monitor: if in TCP fallback, periodically tests UDP recovery
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
						// In TCP fallback: send periodic lightweight UDP probe to test recovery
						_ = udpCh.Send(nil)
						if (now - lastRecv) < 3*time.Second.Nanoseconds() {
							udpActive.Store(true)
							log.Printf("[FAILOVER] UDP data path recovered (verified healthy responses), seamlessly restoring high-speed UDP WebRTC routing")
						}
					}
				case <-tunnel.Done():
					return
				case <-monitorDone:
					return
				}
			}
		}()

		errCh := make(chan error, 3)
		go func() { errCh <- copyTunToData(tun, udpCh, tunnel, &udpActive, cfg.EnableIPv6) }()
		go func() { errCh <- copyUDPToTun(udpCh, tun, &lastUDPRecvNano) }()
		go func() { errCh <- copyTunnelToTun(tunnel, tun) }()
		select {
		case err := <-errCh:
			close(monitorDone)
			return err
		case <-tunnel.Done():
			close(monitorDone)
			return io.EOF
		}
	}

	errCh := make(chan error, 2)
	go func() { errCh <- copyTunToTunnel(tun, tunnel) }()
	go func() { errCh <- copyTunnelToTun(tunnel, tun) }()
	return <-errCh
}

func debugf(format string, args ...any) {
	if debugLogging {
		log.Printf("DEBUG: "+format, args...)
	}
}

func echoTest(tunnel *obsidian.Tunnel) {
	for i := 0; i < 5; i++ {
		msg := []byte(fmt.Sprintf("obsidian ping %d", i))
		log.Printf("→ %s", msg)
		if err := tunnel.SendData(msg); err != nil {
			log.Println("send:", err)
			return
		}
		resp, err := tunnel.RecvData(nil)
		if err != nil {
			log.Println("recv:", err)
			return
		}
		log.Printf("← %s", resp)
		time.Sleep(300 * time.Millisecond)
	}
}

func copyTunToTunnel(tun io.ReadWriter, tunnel *obsidian.Tunnel) error {
	buf := make([]byte, 2048)
	packets := 0
	bytes := 0
	for {
		n, err := tun.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		packets++
		bytes += n

		if err := tunnel.SendData(buf[:n]); err != nil {
			return fmt.Errorf("tunnel send: %w", err)
		}
	}
}

func copyTunnelToTun(tunnel *obsidian.Tunnel, tun io.Writer) error {
	buf := make([]byte, 2048)
	packets := 0
	bytes := 0
	for {
		n, err := tunnel.RecvDataInto(nil, buf)
		if err != nil {
			return fmt.Errorf("tunnel recv: %w", err)
		}
		packets++
		bytes += n

		if _, err := tun.Write(buf[:n]); err != nil {
			return fmt.Errorf("tun write: %w", err)
		}
	}
}

func warmupUDPAddress(ch *obsidian.UDPChannel) {
	// Empty UDP packets are address-learning probes. They make sure the server
	// knows the client's NAT endpoint before the first real DNS/TCP response.
	for i := 0; i < 5; i++ {
		if err := ch.Send(nil); err != nil {
			log.Printf("udp warmup probe %d failed: %v", i+1, err)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

var clientUDPPacketPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func getClientUDPPacketBuf() *[]byte {
	p := clientUDPPacketPool.Get().(*[]byte)
	if cap(*p) < 2048 {
		b := make([]byte, 2048)
		return &b
	}
	*p = (*p)[:2048]
	return p
}

func putClientUDPPacketBuf(p *[]byte) {
	if p != nil && cap(*p) >= 2048 && cap(*p) <= 4096 {
		*p = (*p)[:0]
		clientUDPPacketPool.Put(p)
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

func copyTunToData(tun io.ReadWriter, ch *obsidian.UDPChannel, tunnel *obsidian.Tunnel, udpActive *atomic.Bool, enableIPv6 bool) error {
	pBuf := getClientUDPPacketBuf()
	defer putClientUDPPacketBuf(pBuf)
	sendBuf := make([]byte, 2048)
	packets := 0
	var udpFailCount atomic.Int32
	for {
		buf := (*pBuf)[:cap(*pBuf)]
		n, err := tun.Read(buf)
		if err != nil {
			return fmt.Errorf("tun read: %w", err)
		}
		packet := buf[:n]
		packets++
		if !enableIPv6 && isIPv6Packet(packet) {
			writeIPv6Unreachable(tun, packet)
			continue
		}
		if debugLogging && (packets <= 8 || packets%1000 == 0) {
			log.Printf("DEBUG: TUN -> OUT packet #%d (%d bytes, IPv%d, udpActive=%v)", packets, len(packet), packet[0]>>4, udpActive.Load())
		}
		if udpActive.Load() {
			if err := ch.SendWithBuffer(packet, sendBuf); err != nil {
				if isTemporaryNetworkError(err) {
					continue
				}
				fails := udpFailCount.Add(1)
				if fails >= 5 {
					log.Printf("udp send failed repeatedly (%d times): %v, falling back to TCP REALITY", fails, err)
					udpActive.Store(false)
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

type queuedUDPPacket struct {
	buf *[]byte
	n   int
}

func copyUDPToTun(ch *obsidian.UDPChannel, tun io.Writer, lastUDPRecvNano *atomic.Int64) error {
	queue := make(chan queuedUDPPacket, 2048)
	errCh := make(chan error, 1)

	// Pipelined TUN writer goroutine ensures packet reception is never blocked by TUN driver I/O
	go func() {
		defer close(errCh)
		for qp := range queue {
			if _, err := tun.Write((*qp.buf)[:qp.n]); err != nil {
				putClientUDPPacketBuf(qp.buf)
				errCh <- fmt.Errorf("tun write: %w", err)
				return
			}
			putClientUDPPacketBuf(qp.buf)
		}
	}()

	packets := 0
	for {
		pBuf := getClientUDPPacketBuf()
		n, err := ch.Recv(*pBuf)
		if err != nil {
			putClientUDPPacketBuf(pBuf)
			close(queue)
			return fmt.Errorf("udp recv: %w", err)
		}
		if lastUDPRecvNano != nil && (packets < 16 || packets%64 == 0) {
			lastUDPRecvNano.Store(time.Now().UnixNano())
		}
		packets++
		if debugLogging && (packets <= 8 || packets%1000 == 0) {
			log.Printf("DEBUG: UDP -> TUN packet #%d (%d bytes, IPv%d)", packets, n, (*pBuf)[0]>>4)
		}

		select {
		case queue <- queuedUDPPacket{buf: pBuf, n: n}:
		default:
			putClientUDPPacketBuf(pBuf)
		}

		select {
		case err := <-errCh:
			if err != nil {
				return err
			}
		default:
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

// openTUN is implemented per-platform (tun_windows.go / tun_stub.go)

func isIPv6Packet(packet []byte) bool {
	return len(packet) > 0 && packet[0]>>4 == 6
}

func writeIPv6Unreachable(tun io.Writer, original []byte) {
	reply, err := buildICMPv6DestinationUnreachable(original)
	if err != nil {
		log.Printf("build ICMPv6 unreachable failed: %v", err)
		return
	}
	if _, err := tun.Write(reply); err != nil {
		log.Printf("write ICMPv6 unreachable failed: %v", err)
	}
}

func buildICMPv6DestinationUnreachable(original []byte) ([]byte, error) {
	if len(original) < 40 || original[0]>>4 != 6 {
		return nil, fmt.Errorf("not IPv6")
	}
	origPayloadLen := int(binary.BigEndian.Uint16(original[4:6]))
	origTotalLen := 40 + origPayloadLen
	if origTotalLen > len(original) {
		origTotalLen = len(original)
	}
	quoteLen := origTotalLen
	if quoteLen > 1232-48 {
		quoteLen = 1232 - 48
	}
	payloadLen := 8 + quoteLen
	reply := make([]byte, 40+payloadLen)
	reply[0] = 0x60
	binary.BigEndian.PutUint16(reply[4:6], uint16(payloadLen))
	reply[6] = 58 // ICMPv6
	reply[7] = 64
	copy(reply[8:24], original[24:40])
	copy(reply[24:40], original[8:24])
	icmp := reply[40:]
	icmp[0] = 1 // Destination Unreachable
	icmp[1] = 5 // Source address failed ingress/egress policy
	copy(icmp[8:], original[:quoteLen])
	csum := icmpv6Checksum(reply[8:24], reply[24:40], icmp)
	binary.BigEndian.PutUint16(icmp[2:4], csum)
	return reply, nil
}

func icmpv6Checksum(src, dst, icmp []byte) uint16 {
	sum := checksumAddBytes(0, src)
	sum = checksumAddBytes(sum, dst)
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[0:4], uint32(len(icmp)))
	pseudo[7] = 58
	sum = checksumAddBytes(sum, pseudo[:])
	sum = checksumAddBytes(sum, icmp)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumAddBytes(sum uint32, b []byte) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
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
	// Парсим CPS сигнатуры из конфига
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
