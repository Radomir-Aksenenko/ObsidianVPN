package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	splitModeInclude = "include"
	splitModeExclude = "exclude"
)

func splitTunnelMode(cfg Config) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.SplitTunnelMode))
	switch mode {
	case splitModeInclude, "only", "only_selected", "vpn_only":
		return splitModeInclude
	case splitModeExclude, "except", "all_except", "bypass_selected":
		return splitModeExclude
	}
	if len(splitTunnelEntries(cfg.RouteIPs, nil, nil, nil)) > 0 {
		return splitModeInclude
	}
	return splitModeExclude
}

func splitTunnelEnabled(cfg Config) bool {
	return len(splitTunnelEntries(cfg.RouteIPs, cfg.SplitSites, cfg.SplitApps, cfg.SplitProcesses)) > 0
}

func splitTunnelEntries(routeIPs, sites, apps, processes []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range [][]string{routeIPs, sites, apps, processes} {
		for _, item := range list {
			item = strings.TrimSpace(item)
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

// SplitMatcher manages domain rules, subdomains, wildcards, and CIDR subnets
type SplitMatcher struct {
	exactDomains map[string]bool
	suffixRules  []string
	tldRules     []string
	ipNets       []*net.IPNet
	staticIPs    []string
	domainList   []string
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if idx := strings.IndexAny(d, "/:?#"); idx >= 0 {
		d = d[:idx]
	}
	d = strings.TrimSuffix(d, ".")
	return d
}

// NewSplitMatcher parses a list of domains, wildcards (*.ru, *.рф, *.su), and CIDRs
func NewSplitMatcher(entries []string) *SplitMatcher {
	m := &SplitMatcher{
		exactDomains: make(map[string]bool),
	}

	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		// 1. Try CIDR (e.g. 192.168.0.0/16, 77.88.0.0/18)
		if _, ipNet, err := net.ParseCIDR(raw); err == nil && ipNet != nil {
			m.ipNets = append(m.ipNets, ipNet)
			continue
		}

		// 2. Try single IP (e.g. 1.1.1.1)
		if ip := net.ParseIP(raw); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				m.staticIPs = append(m.staticIPs, ip4.String())
			}
			continue
		}

		// 3. Domain or wildcard rule
		domain := normalizeDomain(raw)
		if domain == "" {
			continue
		}

		// Handle TLD or zone wildcards: *.ru, *.su, *.рф, *.xn--p1ai, .ru, .su, .рф
		cleanRule := domain
		if strings.HasPrefix(cleanRule, "*.") {
			cleanRule = strings.TrimPrefix(cleanRule, "*.")
		} else if strings.HasPrefix(cleanRule, ".") {
			cleanRule = strings.TrimPrefix(cleanRule, ".")
		}

		if isTopLevelZone(cleanRule) {
			m.tldRules = append(m.tldRules, cleanRule)
			if cleanRule == "рф" {
				m.tldRules = append(m.tldRules, "xn--p1ai")
			} else if cleanRule == "xn--p1ai" {
				m.tldRules = append(m.tldRules, "рф")
			}
			m.domainList = append(m.domainList, "*."+cleanRule)
			continue
		}

		m.exactDomains[cleanRule] = true
		m.suffixRules = append(m.suffixRules, "."+cleanRule)
		m.domainList = append(m.domainList, cleanRule)

		// Also handle Cyrillic .рф domains if specified
		if strings.HasSuffix(cleanRule, ".рф") {
			puny := strings.TrimSuffix(cleanRule, ".рф") + ".xn--p1ai"
			m.exactDomains[puny] = true
			m.suffixRules = append(m.suffixRules, "."+puny)
		}
	}

	return m
}

func isTopLevelZone(z string) bool {
	switch z {
	case "ru", "рф", "su", "by", "kz", "ua", "com", "net", "org", "xn--p1ai":
		return true
	default:
		return false
	}
}

// MatchesDomain checks whether a query domain matches exact domains, subdomains, or zone wildcards
func (m *SplitMatcher) MatchesDomain(domain string) bool {
	if m == nil {
		return false
	}
	d := normalizeDomain(domain)
	if d == "" {
		return false
	}

	// 1. Exact match
	if m.exactDomains[d] {
		return true
	}

	// 2. Subdomain match (e.g. esia.gosuslugi.ru matches .gosuslugi.ru)
	for _, suffix := range m.suffixRules {
		if strings.HasSuffix(d, suffix) {
			return true
		}
	}

	// 3. TLD / zone match (e.g. *.ru matches anything ending in .ru)
	for _, tld := range m.tldRules {
		if strings.HasSuffix(d, "."+tld) || d == tld {
			return true
		}
	}

	return false
}

// MatchesIP checks whether an IP falls into configured CIDR ranges
func (m *SplitMatcher) MatchesIP(ip net.IP) bool {
	if m == nil || ip == nil {
		return false
	}
	for _, ipNet := range m.ipNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// StaticRoutes returns route specs for static IPs and CIDR ranges
func (m *SplitMatcher) StaticRoutes() []routeSpec {
	if m == nil {
		return nil
	}
	var routes []routeSpec
	for _, ip := range m.staticIPs {
		routes = append(routes, routeSpec{dest: ip, mask: "255.255.255.255"})
	}
	for _, ipNet := range m.ipNets {
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		mask := ipNet.Mask
		if len(mask) != net.IPv4len {
			continue
		}
		routes = append(routes, routeSpec{
			dest: ip4.Mask(mask).String(),
			mask: fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]),
		})
	}
	return routes
}

// Domains returns clean list of domain rules
func (m *SplitMatcher) Domains() []string {
	if m == nil {
		return nil
	}
	return m.domainList
}

// ParseDNSMessage parses a DNS UDP payload (RFC 1035) and returns the QNAME, whether it's a response, and IPv4 A records
func ParseDNSMessage(data []byte) (qname string, isResponse bool, ips []net.IP) {
	if len(data) < 12 {
		return "", false, nil
	}

	flags := binary.BigEndian.Uint16(data[2:4])
	isResponse = (flags & 0x8000) != 0
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	offset := 12

	// Parse Questions
	for q := 0; q < int(qdCount); q++ {
		name, nextOffset := parseDNSName(data, offset)
		if nextOffset == 0 || nextOffset+4 > len(data) {
			return "", isResponse, nil
		}
		if q == 0 {
			qname = name
		}
		offset = nextOffset + 4 // Skip QTYPE (2) + QCLASS (2)
	}

	if !isResponse || anCount == 0 {
		return qname, isResponse, nil
	}

	// Parse Answers
	for a := 0; a < int(anCount) && offset < len(data); a++ {
		_, nextOffset := parseDNSName(data, offset)
		if nextOffset == 0 || nextOffset+10 > len(data) {
			break
		}
		offset = nextOffset

		rtype := binary.BigEndian.Uint16(data[offset : offset+2])
		// rclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		// ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		if offset+rdLength > len(data) {
			break
		}

		// TYPE 1 = A record (IPv4 address, length 4)
		if rtype == 1 && rdLength == 4 {
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			if ip4 := ip.To4(); ip4 != nil {
				ips = append(ips, ip4)
			}
		}

		offset += rdLength
	}

	return qname, isResponse, ips
}

func parseDNSName(data []byte, offset int) (string, int) {
	var labels []string
	curr := offset
	jumped := false
	nextOffset := 0
	maxJumps := 10
	jumps := 0

	for curr < len(data) {
		length := int(data[curr])
		if length == 0 {
			curr++
			if !jumped {
				nextOffset = curr
			}
			break
		}

		// Pointer (0xC0)
		if (length & 0xC0) == 0xC0 {
			if curr+1 >= len(data) {
				return "", 0
			}
			if !jumped {
				nextOffset = curr + 2
				jumped = true
			}
			pointer := int(binary.BigEndian.Uint16(data[curr:curr+2]) & 0x3FFF)
			if pointer >= len(data) {
				return "", 0
			}
			curr = pointer
			jumps++
			if jumps > maxJumps {
				return "", 0
			}
			continue
		}

		curr++
		if curr+length > len(data) {
			return "", 0
		}
		labels = append(labels, string(data[curr:curr+length]))
		curr += length
	}

	if !jumped {
		nextOffset = curr
	}

	return strings.Join(labels, "."), nextOffset
}
