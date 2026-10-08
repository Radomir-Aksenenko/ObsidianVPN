//go:build linux || darwin

package tun

import (
	"fmt"
	"log"
	"net/netip"
	"os/exec"
	"strings"
)

// runCmd runs a command and returns its output; errors include the output.
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
		}
		return text, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return text, nil
}

func dnsOrDefault(dns string) string {
	dns = strings.TrimSpace(dns)
	if dns == "" {
		return "1.1.1.1"
	}
	return dns
}

type routeArgsFunc func(r route, verb, tunName string, gw gateway) ([]string, error)

// execRoutes is the OS layer of routeManager: it only runs `ip` or `route`.
type execRoutes struct {
	bin     string
	tunName string
	gw4     gateway
	gw6     gateway
	build   routeArgsFunc
}

func (o *execRoutes) run(r route, verb string) error {
	gw := o.gw4
	if r.prefix.Addr().Is6() {
		gw = o.gw6
	}
	args, err := o.build(r, verb, o.tunName, gw)
	if err != nil {
		return err
	}
	_, err = runCmd(o.bin, args...)
	return err
}

func (o *execRoutes) add(r route) error { return o.run(r, "add") }
func (o *execRoutes) del(r route) error { return o.run(r, "delete") }

// netState is everything the platform changed outside the TUN device itself.
type netState struct {
	rm         *routeManager
	restoreDNS func()
}

// setupNetwork installs routes (split tunnel aware) and the DNS server.
// It never fails the device: problems are logged and nil is returned when
// nothing was configured.
func setupNetwork(cfg Config, ops routeOps, applyDNS func() func()) *netState {
	dns := dnsOrDefault(cfg.DNS)
	dnsAddr, dnsErr := netip.ParseAddr(dns)
	if dnsErr != nil {
		log.Printf("ERROR: invalid DNS server %q: %v; DNS will not be changed", dns, dnsErr)
		dns = ""
	} else if dnsAddr.Is6() && !cfg.EnableIPv6 {
		log.Printf("DNS server %s is IPv6 but IPv6 is disabled; DNS will not be changed", dns)
		dns = ""
	}

	mode := cfg.SplitMode
	if mode != SplitModeInclude && mode != SplitModeExclude {
		mode = SplitModeOff
	}

	rm := newRouteManager(ops, mode, cfg.SplitEntries, dns, cfg.ServerHost, cfg.EnableIPv6, nil)
	if err := rm.start(); err != nil {
		log.Printf("ERROR: routes were not installed: %v", err)
		rm.close()
		return nil
	}
	st := &netState{rm: rm}
	if dns != "" && applyDNS != nil {
		st.restoreDNS = applyDNS()
	}
	log.Printf("network configured: split mode=%q, entries=%d, dns=%q", mode, len(cfg.SplitEntries), dns)
	return st
}

func (s *netState) close() {
	if s == nil {
		return
	}
	if s.restoreDNS != nil {
		s.restoreDNS()
	}
	s.rm.close()
}
