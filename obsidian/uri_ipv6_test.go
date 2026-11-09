package obsidian

import "testing"

// A server reached by its IPv6 address: the host must come out without brackets so that
// net.JoinHostPort adds exactly one pair, and survive an encode/parse round trip.
func TestURIParsesIPv6Host(t *testing.T) {
	pubKey := "170a2fec63c53e4a0c6c866d9d08a3304602b3a9090101765af292a469ac1f27"
	raw := "obsidian://" + pubKey + "@[2a0f:cdc6:500:2c73::2]:9443?auth_key=d859d03517492c93bbdf73a10bc10cf1&security=reality&sni=example.com&udp_port=9443#v6"
	cfg, err := ParseURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerHost != "2a0f:cdc6:500:2c73::2" || cfg.ServerPort != "9443" {
		t.Fatalf("host %q port %q", cfg.ServerHost, cfg.ServerPort)
	}
	again, err := ParseURI(EncodeURI(cfg, "v6"))
	if err != nil {
		t.Fatal(err)
	}
	if again.ServerHost != cfg.ServerHost || again.ServerPort != cfg.ServerPort {
		t.Fatalf("round trip changed the address: %q %q", again.ServerHost, again.ServerPort)
	}
}
