//go:build linux

package main

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	tunDevice      = "/dev/net/tun"
	ifnameSize     = 16
	ioctlTUNSETIFF = 0x400454ca
	iffTUN         = 0x0001
	iffNOPI        = 0x1000
	defaultTunMTU  = 1420
)

type ifReq struct {
	Name  [ifnameSize]byte
	Flags uint16
	_     [22]byte
}

type tunFile struct {
	file  *os.File
	iface string
}

func (t *tunFile) Read(buf []byte) (int, error) {
	return t.file.Read(buf)
}

func (t *tunFile) Write(buf []byte) (int, error) {
	return t.file.Write(buf)
}

func (t *tunFile) Close() error {
	log.Printf("closing TUN %s", t.iface)
	return t.file.Close()
}

func openTUN(cfg Config) io.ReadWriteCloser {
	iface := cfg.TunInterface
	if iface == "" {
		iface = "tun0"
	}
	tunAddr := cfg.TunAddress
	if tunAddr == "" {
		tunAddr = "10.8.0.1/24"
	}

	if _, err := netip.ParsePrefix(tunAddr); err != nil {
		log.Printf("invalid tun_address %q: %v", tunAddr, err)
		return nil
	}

	fd, err := syscall.Open(tunDevice, syscall.O_RDWR, 0)
	if err != nil {
		log.Printf("open tun device: %v", err)
		return nil
	}

	var req ifReq
	copy(req.Name[:], iface)
	req.Flags = iffTUN | iffNOPI

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), ioctlTUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		syscall.Close(fd)
		log.Printf("ioctl TUNSETIFF: %v", errno)
		return nil
	}

	// Enable IP forwarding (IPv4, and optionally IPv6)
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
	if cfg.EnableIPv6 {
		os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644)
		os.WriteFile("/proc/sys/net/ipv6/conf/default/forwarding", []byte("1"), 0644)
	}

	// Configure interface. These commands must exist inside the container; if
	// they do not, the TUN fd exists but writes fail with EIO.
	if err := runCmd("ip", "link", "set", iface, "up"); err != nil {
		log.Printf("configure tun link up: %v", err)
		syscall.Close(fd)
		return nil
	}
	if err := runCmd("ip", "addr", "flush", "dev", iface); err != nil {
		log.Printf("configure tun flush addr: %v", err)
	}
	if err := runCmd("ip", "addr", "add", tunAddr, "dev", iface); err != nil {
		log.Printf("configure tun addr: %v", err)
		syscall.Close(fd)
		return nil
	}
	// Dual-Stack IPv6 in-tunnel prefix
	tunAddr6 := ""
	if cfg.EnableIPv6 {
		tunAddr6 = "fd00:8::1/64"
		if err := runCmd("ip", "-6", "addr", "add", tunAddr6, "dev", iface); err != nil {
			log.Printf("configure tun ipv6 addr: %v", err)
		}
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = defaultTunMTU
	} else if mtu > 1420 {
		mtu = 1420
	}
	if err := runCmd("ip", "link", "set", iface, "mtu", fmt.Sprintf("%d", mtu)); err != nil {
		log.Printf("configure tun mtu: %v", err)
	}

	// Setup NAT — use -C to check before adding (idempotent)
	outIface := cfg.OutInterface
	if outIface == "" {
		outIface = detectOutInterface()
	}
	subnet := tunAddr // e.g. "10.8.0.1/24" — iptables accepts this for -s

	// MASQUERADE IPv4
	if exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", subnet, "-o", outIface, "-j", "MASQUERADE").Run() != nil {
		exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-s", subnet, "-o", outIface, "-j", "MASQUERADE").Run()
	}
	// FORWARD rules IPv4
	if exec.Command("iptables", "-C", "FORWARD",
		"-i", iface, "-o", outIface, "-j", "ACCEPT").Run() != nil {
		exec.Command("iptables", "-A", "FORWARD",
			"-i", iface, "-o", outIface, "-j", "ACCEPT").Run()
	}
	if exec.Command("iptables", "-C", "FORWARD",
		"-i", outIface, "-o", iface, "-m", "state",
		"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run() != nil {
		exec.Command("iptables", "-A", "FORWARD",
			"-i", outIface, "-o", iface, "-m", "state",
			"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
	}
	for _, proto := range []string{"udp", "tcp"} {
		if exec.Command("iptables", "-C", "INPUT",
			"-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT").Run() != nil {
			exec.Command("iptables", "-A", "INPUT",
				"-i", iface, "-p", proto, "--dport", "53", "-j", "ACCEPT").Run()
		}
	}
	mss4 := mtu - 40
	for _, dir := range [][2]string{{"-i", iface}, {"-o", iface}} {
		_ = exec.Command("iptables", "-t", "mangle", "-D", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
		_ = exec.Command("iptables", "-t", "mangle", "-D", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss4)).Run()
		var args []string
		if mtu >= 1500 {
			args = []string{"-t", "mangle", "-A", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"}
		} else {
			args = []string{"-t", "mangle", "-A", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss4)}
		}
		exec.Command("iptables", args...).Run()
	}

	// Setup NAT66 (IPv6) if enabled and external IPv6 default route is present
	if cfg.EnableIPv6 {
		outIface6 := detectOutInterfaceIPv6()
		if outIface6 != "" {
			subnet6 := "fd00:8::/64"
			if exec.Command("ip6tables", "-t", "nat", "-C", "POSTROUTING",
				"-s", subnet6, "-o", outIface6, "-j", "MASQUERADE").Run() != nil {
				exec.Command("ip6tables", "-t", "nat", "-A", "POSTROUTING",
					"-s", subnet6, "-o", outIface6, "-j", "MASQUERADE").Run()
			}
			if exec.Command("ip6tables", "-C", "FORWARD",
				"-i", iface, "-o", outIface6, "-j", "ACCEPT").Run() != nil {
				exec.Command("ip6tables", "-A", "FORWARD",
					"-i", iface, "-o", outIface6, "-j", "ACCEPT").Run()
			}
			if exec.Command("ip6tables", "-C", "FORWARD",
				"-i", outIface6, "-o", iface, "-m", "state",
				"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run() != nil {
				exec.Command("ip6tables", "-A", "FORWARD",
					"-i", outIface6, "-o", iface, "-m", "state",
					"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
			}
			// For IPv6, the IP header is 40 bytes (vs 20 on IPv4).
			// Accounting for TCP header (20 bytes) + optional TCP options (Timestamps/SACK = 12-20 bytes),
			// MSS must be MTU - 80 (1280 for MTU 1360) so that IPv6 TCP packets
			// never exceed the TUN MTU (1360). This completely eliminates IPv6 packet drops.
			mss6 := mtu - 80
			if mss6 < 1200 {
				mss6 = 1200
			}
			for _, dir := range [][2]string{{"-i", iface}, {"-o", iface}} {
				_ = exec.Command("ip6tables", "-t", "mangle", "-D", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
				_ = exec.Command("ip6tables", "-t", "mangle", "-D", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss4)).Run()
				_ = exec.Command("ip6tables", "-t", "mangle", "-D", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss6)).Run()
				args := []string{"-t", "mangle", "-A", "FORWARD", dir[0], dir[1], "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", fmt.Sprintf("%d", mss6)}
				exec.Command("ip6tables", args...).Run()
			}
			log.Printf("Dual-Stack IPv6 NAT66 enabled via %s (prefix: %s, MSS: %d)", outIface6, subnet6, mss6)
		} else {
			log.Printf("Dual-Stack IPv6 in-tunnel ULA %s enabled (host has no external IPv6 default route)", tunAddr6)
		}
		log.Printf("TUN %s up, IPv4=%s, IPv6=%s, NAT via %s", iface, tunAddr, tunAddr6, outIface)
	} else {
		log.Printf("TUN %s up, IPv4=%s, IPv6=disabled, NAT via %s", iface, tunAddr, outIface)
	}

	// Use os.File + non-blocking mode so Go's runtime poller manages the fd.
	// This prevents TUN reads from blocking OS threads.
	syscall.SetNonblock(fd, true)
	file := os.NewFile(uintptr(fd), iface)

	t := &tunFile{file: file, iface: iface}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		log.Println("signal received, shutting down...")
		t.Close()
		os.Exit(0)
	}()

	return t
}

func detectOutInterface() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "eth0"
	}
	fields := splitFieldsBytes(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return "eth0"
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}

func splitFieldsBytes(data []byte) []string {
	var fields []string
	start, inField := 0, false
	for i, c := range data {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			if inField {
				fields = append(fields, string(data[start:i]))
				inField = false
			}
		} else {
			if !inField {
				start = i
				inField = true
			}
		}
	}
	if inField {
		fields = append(fields, string(data[start:]))
	}
	return fields
}

func detectOutInterfaceIPv6() string {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	fields := splitFieldsBytes(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

