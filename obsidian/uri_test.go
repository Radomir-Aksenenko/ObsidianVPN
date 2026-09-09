package obsidian

import (
	"testing"
)

func TestURI_ParseAndEncodeRoundTrip(t *testing.T) {
	pubKey := "170a2fec63c53e4a0c6c866d9d08a3304602b3a9090101765af292a469ac1f27"
	rawURI := "obsidian://" + pubKey + "@198.51.100.1:8443?auth_key=d859d03517492c93bbdf73a10bc10cf1&security=reality&sni=www.microsoft.com&udp_port=8443#TestServer"

	cfg, err := ParseURI(rawURI)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if cfg.ServerHost != "198.51.100.1" {
		t.Errorf("expected host 198.51.100.1, got %s", cfg.ServerHost)
	}
	if cfg.ServerPort != "8443" {
		t.Errorf("expected port 8443, got %s", cfg.ServerPort)
	}
	if cfg.ServerPublicKey != pubKey {
		t.Errorf("expected pubKey %s, got %s", pubKey, cfg.ServerPublicKey)
	}
	if !cfg.RealityEnabled {
		t.Errorf("expected reality to be enabled")
	}
	if cfg.RealitySNI != "www.microsoft.com" {
		t.Errorf("expected reality SNI www.microsoft.com, got %s", cfg.RealitySNI)
	}
	if cfg.RealityAuthKey != "d859d03517492c93bbdf73a10bc10cf1" {
		t.Errorf("expected reality auth key, got %s", cfg.RealityAuthKey)
	}
	if cfg.Label != "TestServer" {
		t.Errorf("expected label TestServer, got %s", cfg.Label)
	}

	// Re-encode
	encoded := EncodeURI(cfg, "TestServer")
	cfg2, err := ParseURI(encoded)
	if err != nil {
		t.Fatalf("ParseURI of encoded URI failed: %v", err)
	}

	if cfg2.ServerHost != cfg.ServerHost || cfg2.ServerPort != cfg.ServerPort || cfg2.ServerPublicKey != cfg.ServerPublicKey {
		t.Errorf("roundtrip mismatch: original %+v vs parsed %+v", cfg, cfg2)
	}
	if cfg2.Label != "TestServer" {
		t.Errorf("expected label TestServer, got %s", cfg2.Label)
	}
}

func TestURI_VPNSchemeAlias(t *testing.T) {
	pubKey := "170a2fec63c53e4a0c6c866d9d08a3304602b3a9090101765af292a469ac1f27"
	rawURI := "vpn://obsidian/" + pubKey + "@1.2.3.4:9000?udp_port=9000&mtu=1380#My-Node"

	cfg, err := ParseURI(rawURI)
	if err != nil {
		t.Fatalf("ParseURI with vpn://obsidian/ failed: %v", err)
	}
	if cfg.ServerHost != "1.2.3.4" || cfg.ServerPort != "9000" {
		t.Errorf("host/port mismatch: got %s:%s", cfg.ServerHost, cfg.ServerPort)
	}
	if cfg.MTU != 1380 {
		t.Errorf("expected MTU 1380, got %d", cfg.MTU)
	}
	if cfg.Label != "My-Node" {
		t.Errorf("expected label My-Node, got %s", cfg.Label)
	}

	rawURI2 := "vpn://" + pubKey + "@1.2.3.4:9000?udp_port=9000#DirectVPN"
	cfg2, err := ParseURI(rawURI2)
	if err != nil {
		t.Fatalf("ParseURI with vpn:// failed: %v", err)
	}
	if cfg2.ServerHost != "1.2.3.4" || cfg2.ServerPort != "9000" {
		t.Errorf("host/port mismatch: got %s:%s", cfg2.ServerHost, cfg2.ServerPort)
	}
	if cfg2.Label != "DirectVPN" {
		t.Errorf("expected label DirectVPN, got %s", cfg2.Label)
	}
}
