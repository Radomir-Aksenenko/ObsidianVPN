package main

import "testing"

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
