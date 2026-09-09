// Command probe verifies an Obsidian server without creating a host TUN adapter.
// It is intended for deployment smoke tests and sends one DNS query through the
// configured UDP data channel after completing the authenticated handshake.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"obsidian/obsidian"
)

type config struct {
	ServerHost       string   `json:"server_host"`
	ServerPort       string   `json:"server_port"`
	ServerPublicKey  string   `json:"server_public_key"`
	ClientPrivateKey string   `json:"client_private_key"`
	NoTLS            bool     `json:"no_tls"`
	SNI              string   `json:"sni"`
	SNIPool          []string `json:"sni_pool"`
	VerifyTLS        bool     `json:"verify_tls"`
	DNS              string   `json:"dns"`
	Profile          string   `json:"profile"`
	JunkCount        int      `json:"junk_count"`
	JunkMin          int      `json:"junk_min"`
	JunkMax          int      `json:"junk_max"`
	Signatures       []string `json:"signatures"`
	UDPPort          string   `json:"udp_port"`
	EnableUDPData    bool     `json:"enable_udp_data"`
}

func main() {
	configPath := flag.String("config", "", "path to client JSON configuration")
	timeout := flag.Duration("timeout", 12*time.Second, "end-to-end probe timeout")
	transport := flag.String("transport", "udp", "data path to verify: udp or tcp")
	natTest := flag.Bool("nat-test", false, "query a public resolver to verify VPS forwarding/NAT")
	verbose := flag.Bool("verbose", false, "print detailed non-secret connection diagnostics")
	flag.Parse()
	if *configPath == "" {
		log.Fatal("--config is required")
	}

	cfg, err := readConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *transport != "udp" && *transport != "tcp" {
		log.Fatal("--transport must be udp or tcp")
	}
	if *transport == "udp" && (!cfg.EnableUDPData || cfg.UDPPort == "") {
		log.Fatal("UDP probe requires enable_udp_data=true and udp_port")
	}

	deadline := time.Now().Add(*timeout)
	conn, framer, keys, err := connect(cfg, deadline, *verbose)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if *transport == "udp" {
		probeUDP(cfg, keys, deadline, *natTest)
		return
	}
	tunnel := obsidian.NewTunnel(conn, framer, obsidian.DefaultTunnelConfig())
	defer tunnel.Close()
	probeTCP(tunnel, deadline, cfg.DNS, *natTest)
}

func probeTCP(tunnel *obsidian.Tunnel, deadline time.Time, dns string, natTest bool) {
	if natTest {
		dns = "1.1.1.1"
	}
	query, err := dnsIPv4Query("10.8.0.2", dns, "example.com")
	if err != nil {
		log.Fatal(err)
	}
	if err := tunnel.SendData(query); err != nil {
		log.Fatalf("send TCP DNS query: %v", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	response, err := tunnel.RecvData(ctx)
	if err != nil {
		log.Fatalf("receive TCP DNS response: %v", err)
	}
	if err := validateDNSIPv4Response(response); err != nil {
		log.Fatalf("invalid TCP DNS response: %v", err)
	}
	if natTest {
		log.Printf("OK: authenticated handshake, TCP fallback and VPS internet NAT (%d-byte response)", len(response))
		return
	}
	log.Printf("OK: authenticated handshake and TCP fallback data path (%d-byte response)", len(response))
}

func probeUDP(cfg config, keys *obsidian.SessionKeys, deadline time.Time, natTest bool) {
	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(cfg.ServerHost, cfg.UDPPort))
	if err != nil {
		log.Fatalf("resolve UDP: %v", err)
	}
	udpConn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		log.Fatalf("dial UDP: %v", err)
	}
	defer udpConn.Close()
	channel, err := obsidian.NewUDPChannel(udpConn, obsidian.DeriveUDPKeys(keys, true))
	if err != nil {
		log.Fatalf("create UDP channel: %v", err)
	}
	defer channel.Close()

	// Let the server associate this UDP endpoint with the authenticated session.
	for range 5 {
		if err := channel.Send(nil); err != nil {
			log.Fatalf("UDP warmup: %v", err)
		}
		time.Sleep(40 * time.Millisecond)
	}

	dns := cfg.DNS
	if natTest {
		dns = "1.1.1.1"
	}
	query, err := dnsIPv4Query("10.8.0.2", dns, "example.com")
	if err != nil {
		log.Fatal(err)
	}
	if err := channel.Send(query); err != nil {
		log.Fatalf("send DNS query: %v", err)
	}
	if err := udpConn.SetReadDeadline(deadline); err != nil {
		log.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, err := channel.Recv(buf)
	if err != nil {
		log.Fatalf("receive DNS response: %v", err)
	}
	if err := validateDNSIPv4Response(buf[:n]); err != nil {
		log.Fatalf("invalid DNS response: %v", err)
	}
	if natTest {
		log.Printf("OK: authenticated handshake, UDP data channel and VPS internet NAT (%d-byte response)", n)
		return
	}
	log.Printf("OK: authenticated handshake and UDP DNS data path (%d-byte response)", n)
}

func readConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	var cfg config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("decode config: %w", err)
	}
	if cfg.ServerHost == "" || cfg.ServerPort == "" || cfg.DNS == "" {
		return config{}, errors.New("server_host, server_port and dns are required")
	}
	return cfg, nil
}

func connect(cfg config, deadline time.Time, verbose bool) (net.Conn, *obsidian.StreamFramer, *obsidian.SessionKeys, error) {
	trace := func(format string, args ...any) {
		if verbose {
			log.Printf("DEBUG: "+format, args...)
		}
	}
	serverPub, err := decodeKey(cfg.ServerPublicKey, "server_public_key")
	if err != nil {
		return nil, nil, nil, err
	}
	clientPriv, err := decodeKey(cfg.ClientPrivateKey, "client_private_key")
	if err != nil {
		return nil, nil, nil, err
	}
	clientStatic, err := obsidian.KeypairFromPrivate(clientPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("client key: %w", err)
	}

	var conn net.Conn
	if cfg.NoTLS {
		trace("transport: dialing raw TCP %s:%s", cfg.ServerHost, cfg.ServerPort)
		conn, err = obsidian.DialTCPTimeout(cfg.ServerHost, cfg.ServerPort, time.Until(deadline))
	} else {
		conn, err = obsidian.DialObsidian(obsidian.ClientTransportConfig{
			ServerHost: cfg.ServerHost,
			ServerPort: cfg.ServerPort,
			SNI:        cfg.SNI,
			SNIPool:    cfg.SNIPool,
			VerifyCert: cfg.VerifyTLS,
		})
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect: %w", err)
	}
	trace("transport: connected local=%s remote=%s", conn.LocalAddr(), conn.RemoteAddr())
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("set deadline: %w", err)
	}

	obfCfg, err := obfuscationConfig(cfg)
	if err != nil {
		conn.Close()
		return nil, nil, nil, err
	}
	hs, err := obsidian.NewClientHandshakeWithStaticKey(serverPub, clientStatic, obfCfg)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("handshake init: %w", err)
	}
	for _, build := range []func() ([]byte, error){hs.BuildSignatureTrain, hs.BuildJunkTrain} {
		data, err := build()
		if err != nil {
			conn.Close()
			return nil, nil, nil, err
		}
		if len(data) > 0 {
			trace("handshake: sending preamble chunk (%d bytes)", len(data))
			if _, err := conn.Write(data); err != nil {
				conn.Close()
				return nil, nil, nil, fmt.Errorf("write handshake preamble: %w", err)
			}
		}
	}
	hello, err := hs.BuildHello()
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("build hello: %w", err)
	}
	helloFrame, err := obsidian.BuildHelloFrame(serverPub, hello)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("frame hello: %w", err)
	}
	if _, err := conn.Write(helloFrame); err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("write hello: %w", err)
	}
	trace("handshake: sent ClientHello (%d bytes), waiting for ServerHello", len(helloFrame))
	serverHello, err := obsidian.ReadHelloFrame(conn, serverPub, 16*1024, 8192)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("read server hello: %w (check server_public_key, VPS logs, and traffic filtering)", err)
	}
	trace("handshake: received ServerHello (%d bytes)", len(serverHello))
	framer, err := hs.ProcessServerHello(serverHello)
	if err != nil {
		conn.Close()
		return nil, nil, nil, fmt.Errorf("process server hello: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, framer, hs.SessionKeys, nil
}

func decodeKey(value, field string) ([obsidian.KeySize]byte, error) {
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != obsidian.KeySize {
		return [obsidian.KeySize]byte{}, fmt.Errorf("invalid %s", field)
	}
	var key [obsidian.KeySize]byte
	copy(key[:], b)
	return key, nil
}

func obfuscationConfig(cfg config) (obsidian.ObfuscationConfig, error) {
	oc := obsidian.DefaultObfuscationConfig()
	obsidian.ApplyProfile(cfg.Profile, &obsidian.TunnelConfig{}, &oc)
	if cfg.JunkCount > 0 {
		oc.JunkCount = cfg.JunkCount
	}
	if cfg.JunkMin > 0 {
		oc.JunkMin = cfg.JunkMin
	}
	if cfg.JunkMax > 0 {
		oc.JunkMax = cfg.JunkMax
	}
	if len(cfg.Signatures) > 0 {
		oc.Signatures = nil
		for _, text := range cfg.Signatures {
			sig, err := obsidian.ParseCPS(text)
			if err != nil {
				return oc, fmt.Errorf("parse signature %q: %w", text, err)
			}
			oc.Signatures = append(oc.Signatures, sig)
		}
	}
	return oc, nil
}

func dnsIPv4Query(srcText, dstText, name string) ([]byte, error) {
	src := net.ParseIP(srcText).To4()
	dst := net.ParseIP(dstText).To4()
	if src == nil || dst == nil {
		return nil, errors.New("DNS probe requires IPv4 source and destination")
	}
	labels := strings.Split(name, ".")
	dns := make([]byte, 12)
	binary.BigEndian.PutUint16(dns[0:2], 0x4f42)
	binary.BigEndian.PutUint16(dns[2:4], 0x0100)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("invalid DNS name")
		}
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
	}
	dns = append(dns, 0, 0, 1, 0, 1)

	const ipHeaderLen = 20
	const udpHeaderLen = 8
	packet := make([]byte, ipHeaderLen+udpHeaderLen+len(dns))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], src)
	copy(packet[16:20], dst)
	binary.BigEndian.PutUint16(packet[10:12], ipv4Checksum(packet[:ipHeaderLen]))
	binary.BigEndian.PutUint16(packet[ipHeaderLen:ipHeaderLen+2], 53000)
	binary.BigEndian.PutUint16(packet[ipHeaderLen+2:ipHeaderLen+4], 53)
	binary.BigEndian.PutUint16(packet[ipHeaderLen+4:ipHeaderLen+6], uint16(udpHeaderLen+len(dns)))
	copy(packet[ipHeaderLen+udpHeaderLen:], dns)
	return packet, nil
}

func validateDNSIPv4Response(packet []byte) error {
	if len(packet) < 40 || packet[0]>>4 != 4 || packet[9] != 17 {
		return errors.New("not an IPv4 UDP packet")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+20 {
		return errors.New("truncated IPv4 response")
	}
	if binary.BigEndian.Uint16(packet[ihl:ihl+2]) != 53 || binary.BigEndian.Uint16(packet[ihl+2:ihl+4]) != 53000 {
		return errors.New("unexpected UDP ports")
	}
	dns := packet[ihl+8:]
	if binary.BigEndian.Uint16(dns[0:2]) != 0x4f42 || binary.BigEndian.Uint16(dns[2:4])&0x8000 == 0 {
		return errors.New("unexpected DNS transaction")
	}
	return nil
}

func ipv4Checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
