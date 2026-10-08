//go:build darwin

package tun

import "log"

// applyDNSDarwin sets dns on every enabled network service and returns the
// function that puts the previous servers back.
func applyDNSDarwin(dns string) func() {
	out, err := runCmd("networksetup", "-listallnetworkservices")
	if err != nil {
		log.Printf("ERROR: list network services: %v; DNS not changed", err)
		return func() {}
	}
	saved := make(map[string][]string)
	var order []string
	for _, svc := range parseNetworkServices(out) {
		cur, err := runCmd("networksetup", "-getdnsservers", svc)
		if err != nil {
			log.Printf("DNS: skipping service %q: %v", svc, err)
			continue
		}
		prev := parseDNSServers(cur)
		if _, err := runCmd("networksetup", setDNSArgs(svc, []string{dns})...); err != nil {
			log.Printf("ERROR: set DNS on %q: %v", svc, err)
			continue
		}
		saved[svc] = prev
		order = append(order, svc)
	}
	_, _ = runCmd("dscacheutil", "-flushcache")
	log.Printf("DNS: %s set on %d network service(s)", dns, len(order))
	return func() {
		for _, svc := range order {
			if _, err := runCmd("networksetup", setDNSArgs(svc, saved[svc])...); err != nil {
				log.Printf("ERROR: restore DNS on %q: %v", svc, err)
			}
		}
		_, _ = runCmd("dscacheutil", "-flushcache")
	}
}
