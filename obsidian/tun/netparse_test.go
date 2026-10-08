package tun

import (
	"reflect"
	"testing"
)

func TestParseLinuxDefaultRoute(t *testing.T) {
	g := parseLinuxDefaultRoute("default via 192.168.1.1 dev eth0 proto dhcp metric 100\n")
	if g.ip != "192.168.1.1" || g.dev != "eth0" {
		t.Fatalf("got %+v", g)
	}
	g = parseLinuxDefaultRoute("default dev ppp0 scope link\n")
	if g.ip != "" || g.dev != "ppp0" {
		t.Fatalf("got %+v", g)
	}
	if parseLinuxDefaultRoute("").valid() {
		t.Fatal("empty output must be invalid")
	}
}

func TestParseDarwinDefaultRoute(t *testing.T) {
	out := "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n"
	g := parseDarwinDefaultRoute(out)
	if g.ip != "192.168.1.1" || g.dev != "en0" {
		t.Fatalf("got %+v", g)
	}
	g = parseDarwinDefaultRoute("    gateway: fe80::1\n  interface: en0\n")
	if g.ip != "fe80::1%en0" {
		t.Fatalf("got %+v", g)
	}
}

func TestRouteArgs(t *testing.T) {
	p4 := route{prefix: prefixes("10.0.0.0/8")[0]}
	p6 := route{prefix: prefixes("2001:db8::/32")[0], viaTun: true}
	gw := gateway{ip: "192.168.1.1", dev: "eth0"}

	got, _ := linuxRouteArgs(p4, "add", "tun0", gw)
	if want := []string{"route", "add", "10.0.0.0/8", "via", "192.168.1.1", "dev", "eth0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("linux gw = %v", got)
	}
	got, _ = linuxRouteArgs(p6, "delete", "tun0", gw)
	if want := []string{"-6", "route", "delete", "2001:db8::/32", "dev", "tun0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("linux tun6 = %v", got)
	}
	if _, err := linuxRouteArgs(p4, "add", "tun0", gateway{}); err == nil {
		t.Error("expected error without gateway")
	}

	got, _ = darwinRouteArgs(p4, "add", "utun3", gw)
	if want := []string{"-n", "add", "-net", "10.0.0.0/8", "192.168.1.1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("darwin gw = %v", got)
	}
	got, _ = darwinRouteArgs(p6, "add", "utun3", gw)
	if want := []string{"-n", "add", "-inet6", "-net", "2001:db8::/32", "-interface", "utun3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("darwin tun6 = %v", got)
	}
}

func TestParseNetworkServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100 LAN\n"
	want := []string{"Wi-Fi", "USB 10/100 LAN"}
	if got := parseNetworkServices(out); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseDNSServersAndArgs(t *testing.T) {
	if got := parseDNSServers("There aren't any DNS Servers set on Wi-Fi.\n"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	got := parseDNSServers("192.168.1.1\n8.8.8.8\n")
	if !reflect.DeepEqual(got, []string{"192.168.1.1", "8.8.8.8"}) {
		t.Fatalf("got %v", got)
	}
	if a := setDNSArgs("Wi-Fi", nil); !reflect.DeepEqual(a, []string{"-setdnsservers", "Wi-Fi", "Empty"}) {
		t.Fatalf("got %v", a)
	}
	if a := setDNSArgs("Wi-Fi", got); !reflect.DeepEqual(a, []string{"-setdnsservers", "Wi-Fi", "192.168.1.1", "8.8.8.8"}) {
		t.Fatalf("got %v", a)
	}
}
