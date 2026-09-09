//go:build !linux && !darwin && !windows

package tun

import (
	"errors"
)

// Open returns an error on platforms without direct kernel TUN device creation.
// Use OpenFD with an existing descriptor (e.g. Android VpnService) instead.
func Open(cfg Config) (Device, error) {
	return nil, errors.New("direct TUN creation not supported on this OS; use tun.OpenFD() with a system-provided descriptor")
}
