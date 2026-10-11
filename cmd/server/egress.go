package main

import (
	"fmt"
	"log"
	"net"
)

// parseEgressIP validates the egress_ip / egress_ip6 option. An empty string means
// the option is not set and returns (nil, nil). want6 selects the expected family.
func parseEgressIP(raw string, want6 bool) (net.IP, error) {
	if raw == "" {
		return nil, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("not an IP address")
	}
	is4 := ip.To4() != nil
	if want6 && is4 {
		return nil, fmt.Errorf("not an IPv6 address")
	}
	if !want6 && !is4 {
		return nil, fmt.Errorf("not an IPv4 address")
	}
	return ip, nil
}

// egressIPAssigned reports whether ip is one of the addresses in addrs
// (the output of net.InterfaceAddrs).
func egressIPAssigned(ip net.IP, addrs []net.Addr) bool {
	for _, a := range addrs {
		var local net.IP
		switch v := a.(type) {
		case *net.IPNet:
			local = v.IP
		case *net.IPAddr:
			local = v.IP
		}
		if local != nil && local.Equal(ip) {
			return true
		}
	}
	return false
}

// warnIfEgressUnassigned logs a warning when the egress IP is not on a local interface.
// The server keeps running: the provider may route the IP to this host.
func warnIfEgressUnassigned(name string, ip net.IP) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("WARNING: cannot list local addresses to check %s %s: %v", name, ip, err)
		return
	}
	if !egressIPAssigned(ip, addrs) {
		plen := 128
		if ip.To4() != nil {
			plen = 32
		}
		log.Printf("WARNING: %s %s is not assigned to any local interface. "+
			"The provider must route this IP to this server, otherwise SNAT to it breaks return traffic. "+
			"Assign it with: ip addr add %s/%d dev <iface>", name, ip, ip, plen)
	}
}
