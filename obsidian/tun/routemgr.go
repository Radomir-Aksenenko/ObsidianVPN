package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const domainRefreshInterval = 10 * time.Minute

// route is one routing table entry owned by the VPN.
type route struct {
	prefix netip.Prefix
	viaTun bool // true: out of the TUN device, false: via the original gateway
}

// routeOps is the thin OS layer: it only runs commands.
type routeOps interface {
	add(r route) error
	del(r route) error
}

type lookupFunc func(host string) ([]net.IP, error)

// routeManager installs the planned routes, refreshes domain routes and
// removes everything it installed on close.
type routeManager struct {
	ops        routeOps
	mode       string
	entries    []string
	dns        string
	serverHost string
	ipv6       bool
	lookup     lookupFunc
	interval   time.Duration

	mu       sync.Mutex
	applied  []route
	set      map[route]bool
	resolved map[string][]net.IP
	servers  []net.IP
	closed   bool
	stop     chan struct{}
	wg       sync.WaitGroup
}

func newRouteManager(ops routeOps, mode string, entries []string, dns, serverHost string, ipv6 bool, lookup lookupFunc) *routeManager {
	if lookup == nil {
		lookup = func(host string) ([]net.IP, error) { return lookupIPs(host, ipv6) }
	}
	return &routeManager{
		ops: ops, mode: mode, entries: entries, dns: dns, serverHost: serverHost,
		ipv6: ipv6, lookup: lookup, interval: domainRefreshInterval,
		set: make(map[route]bool), resolved: make(map[string][]net.IP),
		stop: make(chan struct{}),
	}
}

func lookupIPs(host string, ipv6 bool) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
		if !ipv6 && a.IP.To4() == nil {
			continue
		}
		out = append(out, a.IP)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable addresses for %s", host)
	}
	return out, nil
}

// resolveServer turns ServerHost into IPs (IPv4, plus IPv6 when enabled).
func (m *routeManager) resolveServer() error {
	host := strings.Trim(strings.TrimSpace(m.serverHost), "[]")
	if host == "" {
		return fmt.Errorf("server host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		m.servers = []net.IP{ip}
		return nil
	}
	ips, err := m.lookup(host)
	if err != nil {
		return err
	}
	m.servers = ips
	return nil
}

// primaryServer returns the resolved server address: the first IPv4 address,
// else the first IPv6 address.
func (m *routeManager) primaryServer() (netip.Addr, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var v6 netip.Addr
	for _, ip := range m.servers {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if a.Is4() {
			return a, true
		}
		if !v6.IsValid() {
			v6 = a
		}
	}
	return v6, v6.IsValid()
}

// start resolves the server, installs the routes and runs the domain refresher.
func (m *routeManager) start() error {
	if err := m.resolveServer(); err != nil {
		log.Printf("ERROR: cannot resolve server host %q to an IP address: %v", m.serverHost, err)
		if m.mode != SplitModeInclude {
			return fmt.Errorf("resolve server host %q: %w", m.serverHost, err)
		}
		log.Printf("include mode: continuing without a bypass route for the server")
	} else {
		log.Printf("server %s resolves to %v", m.serverHost, m.servers)
	}

	hosts, unresolvable := domainEntries(m.entries)
	if m.mode != SplitModeOff {
		for _, u := range unresolvable {
			log.Printf("split tunnel: skipping %q (zone rules cannot be turned into routes on this OS)", u)
		}
	}
	m.refresh()
	if m.mode != SplitModeOff && len(hosts) > 0 {
		m.wg.Add(1)
		go m.refreshLoop()
	}
	return nil
}

func (m *routeManager) refreshLoop() {
	defer m.wg.Done()
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.refresh()
		}
	}
}

// refresh resolves all domain entries and installs routes that are missing.
// Routes are only added here; they are removed on close.
func (m *routeManager) refresh() {
	fresh := make(map[string][]net.IP)
	if m.mode != SplitModeOff {
		hosts, _ := domainEntries(m.entries)
		var mu sync.Mutex
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, h := range hosts {
			targets := []string{h}
			if !strings.HasPrefix(h, "www.") {
				targets = append(targets, "www."+h)
			}
			for _, tg := range targets {
				wg.Add(1)
				sem <- struct{}{}
				go func(h, tg string) {
					defer wg.Done()
					defer func() { <-sem }()
					ips, err := m.lookup(tg)
					if err != nil {
						if tg == h {
							log.Printf("split tunnel: cannot resolve %s: %v", tg, err)
						}
						return
					}
					mu.Lock()
					fresh[h] = append(fresh[h], ips...)
					mu.Unlock()
				}(h, tg)
			}
		}
		wg.Wait()
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	for h, ips := range fresh {
		m.resolved[h] = ips
	}
	resolved := make(map[string][]net.IP, len(m.resolved))
	for k, v := range m.resolved {
		resolved[k] = v
	}
	m.mu.Unlock()

	viaTun, viaGW := planRoutes(m.mode, m.entries, resolved, m.dns, m.servers, m.ipv6)
	m.apply(viaTun, viaGW)
}

func (m *routeManager) apply(viaTun, viaGW []netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	// Gateway routes first: the server must stay reachable before TUN routes appear.
	for _, p := range viaGW {
		m.addLocked(route{prefix: p, viaTun: false})
	}
	for _, p := range viaTun {
		m.addLocked(route{prefix: p, viaTun: true})
	}
}

func (m *routeManager) addLocked(r route) {
	if m.set[r] {
		return
	}
	if err := m.ops.add(r); err != nil {
		log.Printf("route add %s (%s) failed: %v", r.prefix, viaName(r), err)
		return
	}
	m.set[r] = true
	m.applied = append(m.applied, r)
}

func viaName(r route) string {
	if r.viaTun {
		return "tun"
	}
	return "gateway"
}

// close stops the refresher and removes every route that was installed.
func (m *routeManager) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	close(m.stop)
	m.mu.Unlock()
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.applied) - 1; i >= 0; i-- {
		_ = m.ops.del(m.applied[i])
	}
	m.applied = nil
	m.set = make(map[route]bool)
}
