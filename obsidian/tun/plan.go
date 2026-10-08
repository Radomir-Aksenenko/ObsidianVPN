package tun

import (
	"net"
	"net/netip"
	"strings"
)

// Split tunnel modes understood by the unix route planner.
const (
	SplitModeOff     = ""
	SplitModeInclude = "include"
	SplitModeExclude = "exclude"
)

var (
	defaultRoutesV4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	defaultRoutesV6 = []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
)

// hostKey normalizes a domain entry the same way for planning and resolving.
func hostKey(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if idx := strings.IndexAny(d, "/:?#"); idx >= 0 {
		d = d[:idx]
	}
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	return d
}

// entryPrefix parses an IP or CIDR entry. ok is false when the entry is not
// an IP/CIDR (it is a domain or garbage).
func entryPrefix(entry string) (netip.Prefix, bool) {
	entry = strings.TrimSpace(entry)
	if p, err := netip.ParsePrefix(entry); err == nil {
		return normalizePrefix(p), true
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func normalizePrefix(p netip.Prefix) netip.Prefix {
	a := p.Addr()
	if a.Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		p = netip.PrefixFrom(a.Unmap(), bits)
	}
	return p.Masked()
}

func ipToPrefix(ip net.IP) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// domainEntries returns the hostnames from entries that have to be resolved
// and the entries that cannot be (bare TLD zones such as "*.ru").
func domainEntries(entries []string) (hosts, unresolvable []string) {
	seen := make(map[string]bool)
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		if _, ok := entryPrefix(e); ok {
			continue
		}
		h := hostKey(e)
		if h == "" {
			continue
		}
		if !strings.Contains(h, ".") {
			unresolvable = append(unresolvable, e)
			continue
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts, unresolvable
}

// planRoutes is the OS-neutral route planner.
//
//	off/unknown: default routes (0/1, 128/1, ::/1, 8000::/1) via TUN.
//	exclude:     default routes via TUN; entries and resolved domain IPs via the gateway.
//	include:     no default routes; entries and resolved domain IPs via TUN.
//
// The DNS server is always routed through the TUN and the server IPs always
// go through the original gateway. User entries and the DNS server are dropped
// for IPv6 unless ipv6 is true. The IPv6 default routes are planned in full and
// exclude mode regardless of ipv6: otherwise IPv6 leaves through the physical
// interface, while routed into the TUN it is rejected locally by the core.
func planRoutes(mode string, entries []string, resolved map[string][]net.IP, dns string, serverIPs []net.IP, ipv6 bool) (viaTun, viaGateway []netip.Prefix) {
	keep := func(p netip.Prefix) bool { return p.IsValid() && (ipv6 || p.Addr().Is4()) }

	servers := make(map[netip.Prefix]bool)
	gwSet := make(map[netip.Prefix]bool)
	tunSet := make(map[netip.Prefix]bool)
	addGW := func(p netip.Prefix) {
		if p.IsValid() && !gwSet[p] {
			gwSet[p] = true
			viaGateway = append(viaGateway, p)
		}
	}
	addTun := func(p netip.Prefix) {
		if p.IsValid() && !tunSet[p] && !servers[p] {
			tunSet[p] = true
			viaTun = append(viaTun, p)
		}
	}

	var serverPrefixes []netip.Prefix
	for _, ip := range serverIPs {
		if p, ok := ipToPrefix(ip); ok {
			servers[p] = true
			serverPrefixes = append(serverPrefixes, p)
		}
	}
	for _, p := range serverPrefixes {
		addGW(p)
	}

	// Prefixes coming from the user entries and from resolved domains.
	var split []netip.Prefix
	if mode == SplitModeInclude || mode == SplitModeExclude {
		for _, e := range entries {
			e = strings.TrimSpace(e)
			if e == "" || strings.HasPrefix(e, "#") {
				continue
			}
			if p, ok := entryPrefix(e); ok {
				if !keep(p) {
					continue
				}
				split = append(split, p)
				continue
			}
			for _, ip := range resolved[hostKey(e)] {
				if p, ok := ipToPrefix(ip); ok && keep(p) {
					split = append(split, p)
				}
			}
		}
	}

	// The default routes always include IPv6, whatever ipv6 says (see above).
	addDefaults := func() {
		for _, p := range defaultRoutesV4 {
			addTun(p)
		}
		for _, p := range defaultRoutesV6 {
			addTun(p)
		}
	}

	switch mode {
	case SplitModeInclude:
		for _, p := range split {
			addTun(p)
		}
	case SplitModeExclude:
		addDefaults()
		for _, p := range split {
			addGW(p)
		}
	default:
		addDefaults()
	}

	if a, err := netip.ParseAddr(strings.TrimSpace(dns)); err == nil {
		a = a.Unmap()
		if p := netip.PrefixFrom(a, a.BitLen()); keep(p) {
			addTun(p)
		}
	}
	return viaTun, viaGateway
}
