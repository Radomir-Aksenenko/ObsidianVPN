//go:build !windows

package main

import (
	"io"
	"log"
	"net"
	"net/netip"

	"obsidian/obsidian/tun"
)

func openTUN(cfg Config) io.ReadWriteCloser {
	tunCfg := tun.Config{
		Name:       cfg.TunInterface,
		Address:    cfg.TunAddress,
		MTU:        cfg.MTU,
		DNS:        cfg.DNS,
		ServerHost: cfg.ServerHost,
		EnableIPv6: cfg.EnableIPv6,
	}
	tunCfg.SplitMode, tunCfg.SplitEntries = unixSplitTunnel(cfg)
	dev, err := tun.Open(tunCfg)
	if err != nil {
		log.Printf("failed to open TUN device: %v", err)
		return nil
	}
	return dev
}

// pinServerIP makes every later dial use the server IP that the TUN bypass
// route was planned for. ServerHost may resolve to several addresses, and a
// new lookup at dial time can pick one that has no route. The hostname stays
// the TLS SNI, which the transport would otherwise take from ServerHost.
func pinServerIP(cfg *Config, dev io.ReadWriteCloser) {
	src, ok := dev.(interface{ ServerAddr() (netip.Addr, bool) })
	if !ok || cfg.ServerHost == "" || net.ParseIP(cfg.ServerHost) != nil {
		return
	}
	addr, ok := src.ServerAddr()
	if !ok {
		return
	}
	if cfg.SNI == "" {
		cfg.SNI = cfg.ServerHost
	}
	log.Printf("dialing server %s as %s (bypass route address)", cfg.ServerHost, addr)
	cfg.ServerHost = addr.String()
}
