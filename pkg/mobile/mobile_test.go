package mobile

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"obsidian/obsidian"
)

type dummyProtector struct {
	protectedCount int
}

func (p *dummyProtector) Protect(fd int) bool {
	p.protectedCount++
	return true
}

type dummyStatusListener struct {
	lastStatus string
	lastDetail string
}

func (s *dummyStatusListener) OnStatusChange(status, detail string) {
	s.lastStatus = status
	s.lastDetail = detail
}

type dummyStatsListener struct {
	called bool
}

func (s *dummyStatsListener) OnStats(bytesSent, bytesRecv, txSpeed, rxSpeed int64) {
	s.called = true
}

func TestMobilePacketTunnel(t *testing.T) {
	kp, _ := obsidian.GenerateKeypair()
	cfg := &obsidian.ClientConfig{
		ServerPublicKey: hex.EncodeToString(kp.Public[:]),
		ServerHost:      "127.0.0.1",
		ServerPort:      "59998",
	}
	cfgData, _ := json.Marshal(cfg)
	uri := obsidian.EncodeURI(cfg, "test")

	jsonOut, err := ParseConfigURI(uri)
	if err != nil {
		t.Fatalf("ParseConfigURI failed: %v", err)
	}
	if len(jsonOut) == 0 {
		t.Fatal("expected non-empty json output")
	}

	protector := &dummyProtector{}
	statusListener := &dummyStatusListener{}
	statsListener := &dummyStatsListener{}

	sessID, err := StartPacketTunnel(uri, 1420, protector, statusListener, statsListener)
	if err != nil {
		t.Fatalf("StartPacketTunnel failed: %v", err)
	}
	if sessID == "" {
		t.Fatal("expected non-empty session ID")
	}

	// Test packet injection
	testPkt := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00}
	if err := InjectPacket(sessID, testPkt); err != nil {
		t.Fatalf("InjectPacket failed: %v", err)
	}

	stats, err := GetStats(sessID)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats == nil {
		t.Fatal("expected stats")
	}

	// Test Stop
	if err := StopTunnel(sessID); err != nil {
		t.Fatalf("StopTunnel failed: %v", err)
	}

	_ = cfgData
}

// Error paths only: both inputs fail before any socket is opened.
func TestStartPacketTunnelWithConfigErrors(t *testing.T) {
	badKeyJSON, _ := json.Marshal(&obsidian.ClientConfig{
		ServerPublicKey: "not-a-valid-hex-key",
		ServerHost:      "127.0.0.1",
		ServerPort:      "59998",
	})

	tests := []struct {
		name       string
		configJSON string
	}{
		{name: "invalid json", configJSON: "{not json"},
		{name: "invalid server_public_key", configJSON: string(badKeyJSON)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessID, err := StartPacketTunnelWithConfig(tc.configJSON, 1420, nil, nil, nil)
			if err == nil {
				t.Fatal("expected error")
			}
			if sessID != "" {
				t.Fatalf("expected empty session ID on error, got %q", sessID)
			}
		})
	}
}

// A timed-out ReceivePacket is "no packet", not an error: it must return (nil, nil).
func TestReceivePacketTimeoutReturnsNil(t *testing.T) {
	kp, _ := obsidian.GenerateKeypair()
	cfg := &obsidian.ClientConfig{
		ServerPublicKey: hex.EncodeToString(kp.Public[:]),
		ServerHost:      "127.0.0.1",
		ServerPort:      "59998",
	}
	uri := obsidian.EncodeURI(cfg, "test")

	sessID, err := StartPacketTunnel(uri, 1420, nil, nil, nil)
	if err != nil {
		t.Fatalf("StartPacketTunnel failed: %v", err)
	}
	defer StopTunnel(sessID)

	// Nothing is injected from the server side, so this must time out.
	pkt, err := ReceivePacket(sessID, 20)
	if err != nil {
		t.Fatalf("ReceivePacket on timeout returned error: %v", err)
	}
	if pkt != nil {
		t.Fatalf("expected nil packet on timeout, got %d bytes", len(pkt))
	}

	// Non-blocking poll takes the same "no packet" path.
	if pkt, err := ReceivePacket(sessID, 0); pkt != nil || err != nil {
		t.Fatalf("ReceivePacket(0) = (%v, %v), want (nil, nil)", pkt, err)
	}
}

// Real failures must still surface as errors, not be swallowed as "no packet".
func TestReceivePacketUnknownSessionIsError(t *testing.T) {
	pkt, err := ReceivePacket("sess-does-not-exist", 10)
	if err == nil {
		t.Fatal("expected error for unknown session")
	}
	if pkt != nil {
		t.Fatalf("expected nil packet, got %d bytes", len(pkt))
	}
}

func TestMobileLocalProxy(t *testing.T) {
	err := StartLocalProxy("127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartLocalProxy failed: %v", err)
	}

	// Restarting on another port should succeed
	err = StartLocalProxy("127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartLocalProxy second start failed: %v", err)
	}

	err = StopLocalProxy()
	if err != nil {
		t.Fatalf("StopLocalProxy failed: %v", err)
	}
}
