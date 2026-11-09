package client

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"obsidian/obsidian"
	"obsidian/obsidian/tun"
)

// A UDP path that cannot even be set up must leave the session running on TCP. Before, the
// client returned "dial udp" right after a successful handshake and reconnected forever. The
// server listens on IPv6 loopback, which also covers dialing a server by an IPv6 literal.
func TestSessionStaysUpWhenUDPSetupFails(t *testing.T) {
	probe, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	probe.Close()

	kp, _ := obsidian.GenerateKeypair()
	authKey := "reality-shared-auth-key-32-byte"
	ln, err := obsidian.ListenObsidianREALITY("::1", "0", obsidian.RealityDemuxConfig{
		AuthKey: []byte(authKey), HandshakeTimeout: 3 * time.Second, DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	accepted := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func(conn net.Conn) {
				defer conn.Close()
				helloData, err := obsidian.ReadHelloFrame(conn, kp.Public, 4096, 8192)
				if err != nil {
					return
				}
				sh, _ := obsidian.NewServerHandshake(kp.Private, kp.Public, nil)
				reply, framer, err := sh.ProcessClientHello(helloData)
				if err != nil {
					return
				}
				frame, _ := obsidian.BuildHelloFrame(kp.Public, reply)
				if _, err := conn.Write(frame); err != nil {
					return
				}
				tn := obsidian.NewTunnel(conn, framer, obsidian.DefaultTunnelConfig())
				<-tn.Done()
			}(conn)
		}
	}()

	cfg := &obsidian.ClientConfig{
		ServerPublicKey: hex.EncodeToString(kp.Public[:]),
		ServerHost:      "::1",
		ServerPort:      port,
		RealityEnabled:  true,
		RealityAuthKey:  hex.EncodeToString([]byte(authKey)),
		RealitySNI:      "example.com",
		UDPPort:         "not-a-port", // the UDP dial fails after the handshake
		EnableUDPData:   true,
	}
	connected := make(chan struct{}, 8)
	session, err := NewSession(cfg, WithStatusCallback(func(st, _ string) {
		if st == StatusConnected {
			connected <- struct{}{}
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	dev := tun.NewPacketDevice("test-tun", 1420, 64)
	defer dev.Close()
	session.StartAsync(dev)
	defer session.Stop()

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatalf("session never connected, status %q", session.Status())
	}
	time.Sleep(1500 * time.Millisecond)
	if st := session.Status(); st != StatusConnected {
		t.Fatalf("session dropped after the UDP failure: status %q", st)
	}
	if n := len(accepted); n != 1 {
		t.Fatalf("server saw %d connections, want exactly 1 (no reconnect)", n)
	}
	if p := session.GetStats().ActiveDataProtocol; p != "TCP" {
		t.Fatalf("active protocol %q, want TCP", p)
	}
}
