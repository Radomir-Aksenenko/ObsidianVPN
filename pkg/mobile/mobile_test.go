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
