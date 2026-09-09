package client

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"obsidian/obsidian"
	"obsidian/obsidian/tun"
)

func TestNewSessionValidation(t *testing.T) {
	_, err := NewSession(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}

	cfg := &obsidian.ClientConfig{}
	_, err = NewSession(cfg)
	if err == nil {
		t.Fatal("expected error for empty server public key")
	}

	kp, _ := obsidian.GenerateKeypair()
	cfg.ServerPublicKey = hex.EncodeToString(kp.Public[:])
	cfg.ServerHost = "127.0.0.1"
	cfg.ServerPort = "443"

	session, err := NewSession(cfg, WithDebug(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.Status() != StatusDisconnected {
		t.Fatalf("expected initial status %s, got %s", StatusDisconnected, session.Status())
	}

	stats := session.GetStats()
	if stats.Status != StatusDisconnected {
		t.Fatalf("expected stats status %s, got %s", StatusDisconnected, stats.Status)
	}
}

func TestSocks5ProxyNegotiation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	proxy, err := StartSocks5Proxy(addr)
	if err != nil {
		t.Fatalf("StartSocks5Proxy failed: %v", err)
	}
	defer proxy.Close()

	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatalf("dial socks5 failed: %v", err)
	}
	defer conn.Close()

	// 1. Send SOCKS5 greeting
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	resp := make([]byte, 2)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(resp)
	if err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected greeting response: %#v", resp)
	}
}

func TestSessionWithPacketDevice(t *testing.T) {
	kp, _ := obsidian.GenerateKeypair()
	cfg := &obsidian.ClientConfig{
		ServerPublicKey: hex.EncodeToString(kp.Public[:]),
		ServerHost:      "127.0.0.1",
		ServerPort:      "59999", // non-listening port
	}

	var statuses []string
	session, err := NewSession(cfg,
		WithAutoReconnect(false),
		WithStatusCallback(func(status, detail string) {
			statuses = append(statuses, status)
		}),
	)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	dev := tun.NewPacketDevice("test-tun", 1420, 64)
	defer dev.Close()

	// Running against non-listening port should attempt to connect and fail cleanly without panic
	err = session.Start(dev)
	if err == nil {
		t.Fatal("expected connection error")
	}
	if len(statuses) == 0 {
		t.Fatal("expected status callback to be invoked")
	}
}
