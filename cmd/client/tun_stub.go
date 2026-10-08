//go:build !windows

package main

import (
	"io"
	"log"

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
