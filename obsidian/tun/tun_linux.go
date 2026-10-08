//go:build linux

package tun

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_pad  [22]byte
}

type linuxDevice struct {
	file      *os.File
	name      string
	mtu       int
	net       *netState
	closeOnce sync.Once
	closeErr  error
}

func (d *linuxDevice) Read(b []byte) (int, error) {
	return d.file.Read(b)
}

func (d *linuxDevice) Write(b []byte) (int, error) {
	return d.file.Write(b)
}

// Close restores routes and DNS and removes the interface. It is idempotent.
func (d *linuxDevice) Close() error {
	d.closeOnce.Do(func() {
		d.net.close()
		_ = exec.Command("ip", "link", "set", "dev", d.name, "down").Run()
		d.closeErr = d.file.Close()
	})
	return d.closeErr
}

func (d *linuxDevice) Name() string {
	return d.name
}

func (d *linuxDevice) MTU() int {
	return d.mtu
}

// Open creates and configures a native Linux TUN device via /dev/net/tun.
func Open(cfg Config) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (ensure CAP_NET_ADMIN or root)", err)
	}

	var req ifreq
	req.Flags = unix.IFF_TUN | unix.IFF_NO_PI
	if cfg.Name != "" {
		copy(req.Name[:], cfg.Name)
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	actualName := unix.ByteSliceToString(req.Name[:])
	file := os.NewFile(uintptr(fd), actualName)

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	// Configure MTU
	if err := exec.Command("ip", "link", "set", "dev", actualName, "mtu", strconv.Itoa(mtu)).Run(); err != nil {
		file.Close()
		return nil, fmt.Errorf("set mtu %d on %s: %w", mtu, actualName, err)
	}

	// Configure IP address
	addr := cfg.Address
	if addr == "" {
		addr = "10.8.0.2/24"
	}
	if _, err := netip.ParsePrefix(addr); err != nil {
		file.Close()
		return nil, fmt.Errorf("invalid tun address %q: %w", addr, err)
	}

	if err := exec.Command("ip", "addr", "add", addr, "dev", actualName).Run(); err != nil {
		file.Close()
		return nil, fmt.Errorf("set ip address %s on %s: %w", addr, actualName, err)
	}

	// Not fatal: the kernel may have IPv6 disabled.
	if tunWantsIPv6(cfg) {
		if _, err := runCmd("ip", "-6", "addr", "add", tunIPv6Addr+"/64", "dev", actualName); err != nil {
			log.Printf("WARNING: set ipv6 address %s/64 on %s: %v", tunIPv6Addr, actualName, err)
		}
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", "dev", actualName, "up").Run(); err != nil {
		file.Close()
		return nil, fmt.Errorf("bring up %s: %w", actualName, err)
	}

	dev := &linuxDevice{
		file: file,
		name: actualName,
		mtu:  mtu,
	}

	// Without ServerHost the old behavior is kept: no routes are touched.
	if cfg.ServerHost != "" {
		gw4 := findDefaultGatewayLinux("-4")
		var gw6 gateway
		if cfg.EnableIPv6 {
			gw6 = findDefaultGatewayLinux("-6")
		}
		if !gw4.valid() && cfg.SplitMode != SplitModeInclude {
			log.Printf("ERROR: default gateway not found; routes and DNS were not configured")
		} else {
			ops := &execRoutes{bin: "ip", tunName: actualName, gw4: gw4, gw6: gw6, build: linuxRouteArgs}
			dev.net = setupNetwork(cfg, ops, func() func() { return applyDNSLinux(actualName, dnsOrDefault(cfg.DNS)) })
		}
	}

	return dev, nil
}

// ServerAddr returns the server IP the bypass route was planned for, so that
// the client can dial the same address (see netState.serverAddr).
func (d *linuxDevice) ServerAddr() (netip.Addr, bool) {
	return d.net.serverAddr()
}

func findDefaultGatewayLinux(family string) gateway {
	out, err := exec.Command("ip", family, "route", "show", "default").Output()
	if err != nil {
		return gateway{}
	}
	return parseLinuxDefaultRoute(string(out))
}
