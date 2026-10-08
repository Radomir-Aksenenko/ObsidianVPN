package tun

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestPlanRoutes(t *testing.T) {
	server := []net.IP{net.ParseIP("203.0.113.5")}
	resolved := map[string][]net.IP{
		"example.com": {net.ParseIP("93.184.216.34"), net.ParseIP("2606:2800:220:1::1")},
	}
	tests := []struct {
		name     string
		mode     string
		entries  []string
		resolved map[string][]net.IP
		dns      string
		servers  []net.IP
		ipv6     bool
		wantTun  []string
		wantGW   []string
	}{
		{
			name: "off full tunnel ignores entries", mode: SplitModeOff,
			entries: []string{"10.0.0.0/8"}, dns: "1.1.1.1", servers: server,
			wantTun: []string{"0.0.0.0/1", "128.0.0.0/1", "1.1.1.1/32"},
			wantGW:  []string{"203.0.113.5/32"},
		},
		{
			name: "off with ipv6", mode: SplitModeOff, dns: "1.1.1.1", servers: server, ipv6: true,
			wantTun: []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "1.1.1.1/32"},
			wantGW:  []string{"203.0.113.5/32"},
		},
		{
			name: "exclude ips cidr and domains via gateway", mode: SplitModeExclude,
			entries:  []string{"192.168.0.0/16", "8.8.8.8", "example.com", "*.example.com"},
			resolved: resolved, dns: "1.1.1.1", servers: server,
			wantTun: []string{"0.0.0.0/1", "128.0.0.0/1", "1.1.1.1/32"},
			wantGW:  []string{"203.0.113.5/32", "192.168.0.0/16", "8.8.8.8/32", "93.184.216.34/32"},
		},
		{
			name: "exclude with ipv6 keeps v6 entries", mode: SplitModeExclude, ipv6: true,
			entries:  []string{"example.com", "2001:db8::/32"},
			resolved: resolved, dns: "2606:4700:4700::1111", servers: server,
			wantTun: []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "2606:4700:4700::1111/128"},
			wantGW:  []string{"203.0.113.5/32", "93.184.216.34/32", "2606:2800:220:1::1/128", "2001:db8::/32"},
		},
		{
			name: "include has no default routes", mode: SplitModeInclude,
			entries:  []string{"10.1.2.3/24", "example.com"},
			resolved: resolved, dns: "1.1.1.1", servers: server,
			wantTun: []string{"10.1.2.0/24", "93.184.216.34/32", "1.1.1.1/32"},
			wantGW:  []string{"203.0.113.5/32"},
		},
		{
			name: "include unresolved domain adds nothing", mode: SplitModeInclude,
			entries: []string{"nope.example.org"}, dns: "1.1.1.1",
			wantTun: []string{"1.1.1.1/32"},
		},
		{
			name: "server ip is never routed via tun", mode: SplitModeInclude,
			entries: []string{"203.0.113.5", "203.0.113.0/24"}, dns: "203.0.113.5", servers: server,
			wantTun: []string{"203.0.113.0/24"},
			wantGW:  []string{"203.0.113.5/32"},
		},
		{
			name: "dedupe and mapped addresses", mode: SplitModeExclude,
			entries: []string{"8.8.8.8", "8.8.8.8/32", " 8.8.8.8 ", "::ffff:8.8.8.8", "8.8.8.9/24"},
			dns:     "1.1.1.1",
			wantTun: []string{"0.0.0.0/1", "128.0.0.0/1", "1.1.1.1/32"},
			wantGW:  []string{"8.8.8.8/32", "8.8.8.0/24"},
		},
		{
			name: "ipv6 entries dropped without ipv6", mode: SplitModeInclude,
			entries: []string{"2001:db8::1", "10.0.0.1"}, dns: "1.1.1.1",
			wantTun: []string{"10.0.0.1/32", "1.1.1.1/32"},
		},
		{
			name: "unknown mode is full tunnel", mode: "weird", dns: "", servers: server,
			wantTun: []string{"0.0.0.0/1", "128.0.0.0/1"},
			wantGW:  []string{"203.0.113.5/32"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotTun, gotGW := planRoutes(tc.mode, tc.entries, tc.resolved, tc.dns, tc.servers, tc.ipv6)
			if !reflect.DeepEqual(gotTun, prefixes(tc.wantTun...)) {
				t.Errorf("viaTun = %v, want %v", gotTun, tc.wantTun)
			}
			if !reflect.DeepEqual(gotGW, prefixes(tc.wantGW...)) {
				t.Errorf("viaGateway = %v, want %v", gotGW, tc.wantGW)
			}
		})
	}
}

func TestDomainEntries(t *testing.T) {
	hosts, skipped := domainEntries([]string{
		"Example.com", "https://example.com/path", "*.sub.example.org", "1.2.3.4", "10.0.0.0/8",
		"*.ru", "", "# comment", "рф",
	})
	if want := []string{"example.com", "sub.example.org"}; !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %v, want %v", hosts, want)
	}
	if want := []string{"*.ru", "рф"}; !reflect.DeepEqual(skipped, want) {
		t.Errorf("skipped = %v, want %v", skipped, want)
	}
}
