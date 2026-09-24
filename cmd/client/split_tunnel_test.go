package main

import (
	"net"
	"testing"
)

func TestSplitTunnelModeDefaultsLegacyRouteIPsToInclude(t *testing.T) {
	cfg := Config{RouteIPs: []string{"1.1.1.1"}}

	if got := splitTunnelMode(cfg); got != splitModeInclude {
		t.Fatalf("splitTunnelMode() = %q, want %q", got, splitModeInclude)
	}
}

func TestSplitTunnelModeDefaultsFullTunnelToExclude(t *testing.T) {
	cfg := Config{}

	if got := splitTunnelMode(cfg); got != splitModeExclude {
		t.Fatalf("splitTunnelMode() = %q, want %q", got, splitModeExclude)
	}
}

func TestSplitTunnelEntriesTrimAndDeduplicate(t *testing.T) {
	got := splitTunnelEntries(
		[]string{" 1.1.1.1 ", "1.1.1.1", ""},
		[]string{"example.com", "EXAMPLE.com ", "  "},
		[]string{"chrome.exe", "chrome.exe"},
		[]string{" Telegram ", "Telegram"},
	)
	want := []string{"1.1.1.1", "example.com", "EXAMPLE.com", "chrome.exe", "Telegram"}

	if len(got) != len(want) {
		t.Fatalf("len(splitTunnelEntries()) = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitTunnelEntries()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitTunnelEnabledUsesSitesAndApps(t *testing.T) {
	if !splitTunnelEnabled(Config{SplitSites: []string{"example.com"}}) {
		t.Fatal("splitTunnelEnabled() is false for split sites")
	}
	if !splitTunnelEnabled(Config{SplitApps: []string{"chrome.exe"}}) {
		t.Fatal("splitTunnelEnabled() is false for split apps")
	}
	if !splitTunnelEnabled(Config{SplitProcesses: []string{"Telegram"}}) {
		t.Fatal("splitTunnelEnabled() is false for split processes")
	}
	if splitTunnelEnabled(Config{}) {
		t.Fatal("splitTunnelEnabled() is true for empty config")
	}
}

func TestSplitMatcherDomainAndSubdomain(t *testing.T) {
	matcher := NewSplitMatcher([]string{
		"gosuslugi.ru",
		"sberbank.ru",
		"*.yandex.ru",
	})

	// Exact domain
	if !matcher.MatchesDomain("gosuslugi.ru") {
		t.Error("expected gosuslugi.ru to match")
	}
	// Subdomains
	if !matcher.MatchesDomain("esia.gosuslugi.ru") {
		t.Error("expected esia.gosuslugi.ru to match")
	}
	if !matcher.MatchesDomain("online.sberbank.ru") {
		t.Error("expected online.sberbank.ru to match")
	}
	if !matcher.MatchesDomain("mail.yandex.ru") {
		t.Error("expected mail.yandex.ru to match")
	}
	// Negative
	if matcher.MatchesDomain("google.com") {
		t.Error("google.com should not match")
	}
	if matcher.MatchesDomain("notgosuslugi.ru") {
		t.Error("notgosuslugi.ru should not match")
	}
}

func TestSplitMatcherTLDWildcards(t *testing.T) {
	matcher := NewSplitMatcher([]string{
		"*.ru",
		"*.рф",
		"*.su",
	})

	if !matcher.MatchesDomain("kinopoisk.ru") {
		t.Error("expected kinopoisk.ru to match *.ru")
	}
	if !matcher.MatchesDomain("sub.deep.site.ru") {
		t.Error("expected sub.deep.site.ru to match *.ru")
	}
	if !matcher.MatchesDomain("президент.рф") {
		t.Error("expected президент.рф to match *.рф")
	}
	if !matcher.MatchesDomain("test.xn--p1ai") {
		t.Error("expected test.xn--p1ai to match *.рф")
	}
	if !matcher.MatchesDomain("portal.su") {
		t.Error("expected portal.su to match *.su")
	}
	if matcher.MatchesDomain("example.com") {
		t.Error("example.com should not match *.ru")
	}
}

func TestSplitMatcherCIDRAndStaticIPs(t *testing.T) {
	matcher := NewSplitMatcher([]string{
		"192.168.0.0/16",
		"10.8.0.5",
	})

	if !matcher.MatchesIP(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to match CIDR")
	}
	if matcher.MatchesIP(net.ParseIP("172.16.0.1")) {
		t.Error("172.16.0.1 should not match")
	}

	routes := matcher.StaticRoutes()
	if len(routes) != 2 {
		t.Fatalf("expected 2 static routes, got %d", len(routes))
	}
}

func TestParseDNSMessage(t *testing.T) {
	// Sample DNS query for "example.com"
	query := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// QNAME: 7'example'3'com'0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
	}

	qname, isResp, ips := ParseDNSMessage(query)
	if isResp {
		t.Error("expected query, got response")
	}
	if qname != "example.com" {
		t.Errorf("got qname %q, want example.com", qname)
	}
	if len(ips) != 0 {
		t.Errorf("expected 0 ips in query, got %d", len(ips))
	}

	// Sample DNS response for "example.com" with IP 93.184.216.34
	resp := []byte{
		0x12, 0x34, // ID
		0x81, 0x80, // Response, NoError
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x01, // ANCOUNT = 1
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// QNAME
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
		// ANSWER: pointer to offset 12 (0xc0 0x0c)
		0xc0, 0x0c,
		0x00, 0x01, // TYPE = A
		0x00, 0x01, // CLASS = IN
		0x00, 0x00, 0x00, 0x3c, // TTL = 60
		0x00, 0x04, // RDLENGTH = 4
		93, 184, 216, 34, // IP
	}

	qname, isResp, ips = ParseDNSMessage(resp)
	if !isResp {
		t.Error("expected response, got query")
	}
	if qname != "example.com" {
		t.Errorf("got qname %q, want example.com", qname)
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Errorf("got ips %v, want [93.184.216.34]", ips)
	}
}
