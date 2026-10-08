package tun

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeOps struct {
	mu   sync.Mutex
	adds []route
	dels []route
}

func (f *fakeOps) add(r route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, r)
	return nil
}

func (f *fakeOps) del(r route) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dels = append(f.dels, r)
	return nil
}

func (f *fakeOps) addCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.adds)
}

func TestRouteManagerResolvesServerDomainAndCleansUp(t *testing.T) {
	ops := &fakeOps{}
	lookup := func(host string) ([]net.IP, error) {
		if host == "vpn.example.net" {
			return []net.IP{net.ParseIP("198.51.100.7")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	m := newRouteManager(ops, SplitModeOff, nil, "1.1.1.1", "vpn.example.net", false, lookup)
	if err := m.start(); err != nil {
		t.Fatal(err)
	}
	if got := ops.adds[0]; got.viaTun || got.prefix.String() != "198.51.100.7/32" {
		t.Fatalf("first route = %+v, want server /32 via gateway", got)
	}
	if len(ops.adds) != 4 {
		t.Fatalf("adds = %d, want 4", len(ops.adds))
	}
	m.close()
	m.close() // idempotent
	if len(ops.dels) != 4 {
		t.Fatalf("dels = %d, want 4", len(ops.dels))
	}
	if ops.dels[3] != ops.adds[0] {
		t.Fatalf("routes must be removed in reverse order")
	}
}

func TestRouteManagerServerResolveFailure(t *testing.T) {
	lookup := func(string) ([]net.IP, error) { return nil, errors.New("nxdomain") }
	for _, mode := range []string{SplitModeOff, SplitModeExclude} {
		ops := &fakeOps{}
		m := newRouteManager(ops, mode, nil, "1.1.1.1", "vpn.invalid", false, lookup)
		if err := m.start(); err == nil {
			t.Fatalf("mode %q: expected error", mode)
		}
		if ops.addCount() != 0 {
			t.Fatalf("mode %q: routes added despite resolve failure", mode)
		}
	}
	ops := &fakeOps{}
	m := newRouteManager(ops, SplitModeInclude, []string{"10.0.0.0/8"}, "1.1.1.1", "vpn.invalid", false, lookup)
	if err := m.start(); err != nil {
		t.Fatalf("include mode should continue: %v", err)
	}
	m.close()
}

func TestRouteManagerRefreshAddsOnlyNewIPs(t *testing.T) {
	ops := &fakeOps{}
	var mu sync.Mutex
	answers := []net.IP{net.ParseIP("93.184.216.34")}
	lookup := func(host string) ([]net.IP, error) {
		mu.Lock()
		defer mu.Unlock()
		if host == "example.com" {
			return append([]net.IP(nil), answers...), nil
		}
		return nil, errors.New("nxdomain")
	}
	m := newRouteManager(ops, SplitModeInclude, []string{"example.com"}, "1.1.1.1", "203.0.113.5", false, lookup)
	m.interval = 20 * time.Millisecond
	if err := m.start(); err != nil {
		t.Fatal(err)
	}
	initial := ops.addCount() // server, example.com IP, dns
	if initial != 3 {
		t.Fatalf("initial adds = %d, want 3", initial)
	}
	mu.Lock()
	answers = append(answers, net.ParseIP("93.184.216.35"))
	mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for ops.addCount() == initial && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	m.close()
	if got := ops.addCount(); got != initial+1 {
		t.Fatalf("adds after refresh = %d, want %d (no duplicates)", got, initial+1)
	}
	if len(ops.dels) != initial+1 {
		t.Fatalf("dels = %d, want %d", len(ops.dels), initial+1)
	}
}
