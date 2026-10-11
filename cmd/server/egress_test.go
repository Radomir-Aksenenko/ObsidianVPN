package main

import (
	"net"
	"testing"
)

func TestParseEgressIPv4(t *testing.T) {
	ip, err := parseEgressIP("203.0.113.10", false)
	if err != nil {
		t.Fatalf("valid IPv4 rejected: %v", err)
	}
	if ip.To4() == nil || !ip.Equal(net.ParseIP("203.0.113.10")) {
		t.Fatalf("unexpected parse result: %v", ip)
	}
}

func TestParseEgressInvalidString(t *testing.T) {
	for _, raw := range []string{"not-an-ip", "203.0.113", "203.0.113.10/32", "999.1.1.1"} {
		if _, err := parseEgressIP(raw, false); err == nil {
			t.Errorf("%q: expected error", raw)
		}
		if _, err := parseEgressIP(raw, true); err == nil {
			t.Errorf("%q (v6 mode): expected error", raw)
		}
	}
}

func TestParseEgressIPv6PassedAsIPv4(t *testing.T) {
	if _, err := parseEgressIP("2001:db8::10", false); err == nil {
		t.Fatal("IPv6 address accepted as egress_ip")
	}
}

func TestParseEgressIPv4PassedAsIPv6(t *testing.T) {
	if _, err := parseEgressIP("203.0.113.10", true); err == nil {
		t.Fatal("IPv4 address accepted as egress_ip6")
	}
}

func TestParseEgressIPv6(t *testing.T) {
	ip, err := parseEgressIP("2001:db8::10", true)
	if err != nil {
		t.Fatalf("valid IPv6 rejected: %v", err)
	}
	if ip.To4() != nil {
		t.Fatalf("IPv6 parsed as IPv4: %v", ip)
	}
}

func TestParseEgressEmpty(t *testing.T) {
	for _, want6 := range []bool{false, true} {
		ip, err := parseEgressIP("", want6)
		if err != nil || ip != nil {
			t.Fatalf("empty (v6=%v): got ip=%v err=%v, want nil, nil", want6, ip, err)
		}
	}
}

func TestEgressIPAssigned(t *testing.T) {
	addrs := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.0.2.5"), Mask: net.CIDRMask(24, 32)},
		&net.IPAddr{IP: net.ParseIP("2001:db8::5")},
	}
	if !egressIPAssigned(net.ParseIP("192.0.2.5"), addrs) {
		t.Error("assigned IPv4 not found")
	}
	if !egressIPAssigned(net.ParseIP("2001:db8::5"), addrs) {
		t.Error("assigned IPv6 not found")
	}
	if egressIPAssigned(net.ParseIP("203.0.113.10"), addrs) {
		t.Error("unassigned IPv4 reported as assigned")
	}
	if egressIPAssigned(net.ParseIP("203.0.113.10"), nil) {
		t.Error("empty address list reported an assignment")
	}
}
