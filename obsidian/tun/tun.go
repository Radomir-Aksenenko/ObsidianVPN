package tun

import (
	"io"
)

// Device represents a cross-platform TUN network interface.
type Device interface {
	io.ReadWriteCloser
	Name() string
	MTU() int
}

// Config specifies parameters for creating or configuring a TUN device.
type Config struct {
	Name         string
	Address      string // CIDR, e.g. "10.8.0.2/24"
	MTU          int
	DNS          string
	SecondaryDNS string
	ServerHost   string // Needed for routing table configuration
}

// DefaultMTU is the default MTU for Obsidian tunnels.
const DefaultMTU = 1420
