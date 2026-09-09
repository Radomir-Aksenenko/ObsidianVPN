//go:build windows

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	wintunRingCapacity = 0x800000 // 8 MiB
)

type wintunDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle
	name     string
	mtu      int
	serverIP string
	origGW   string
	ifIndex  string
	writeMu  sync.Mutex
}

func (w *wintunDevice) Read(buf []byte) (int, error) {
	for {
		runtime.KeepAlive(w.adapter)
		pkt, err := w.session.ReceivePacket()
		if err == nil {
			n := copy(buf, pkt)
			w.session.ReleaseReceivePacket(pkt)
			return n, nil
		}
		errNo, ok := err.(syscall.Errno)
		if ok && errNo == windows.ERROR_NO_MORE_ITEMS {
			windows.WaitForSingleObject(w.readWait, windows.INFINITE)
			continue
		}
		return 0, err
	}
}

func (w *wintunDevice) Write(buf []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	runtime.KeepAlive(w.adapter)
	pkt, err := w.session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, err
	}
	copy(pkt, buf)
	w.session.SendPacket(pkt)
	return len(buf), nil
}

func (w *wintunDevice) Close() error {
	if w.serverIP != "" {
		_ = exec.Command("route", "delete", w.serverIP).Run()
	}
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("ipconfig", "/flushdns").Run()

	w.session.End()
	w.adapter.Close()
	return nil
}

func (w *wintunDevice) Name() string {
	return w.name
}

func (w *wintunDevice) MTU() int {
	return w.mtu
}

// Open creates and configures a Wintun adapter on Windows.
func Open(cfg Config) (Device, error) {
	ifName := cfg.Name
	if ifName == "" {
		ifName = "ObsidianVPN"
	}
	tunAddr := cfg.Address
	if tunAddr == "" {
		tunAddr = "10.8.0.2/24"
	}

	adapter, err := wintun.CreateAdapter(ifName, "Wintun", nil)
	if err != nil {
		return nil, fmt.Errorf("wintun create adapter: %w (requires Administrator)", err)
	}
	runtime.SetFinalizer(adapter, nil)

	prefix, err := netip.ParsePrefix(tunAddr)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("invalid tun address %q: %w", tunAddr, err)
	}

	session, err := adapter.StartSession(wintunRingCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("wintun start session: %w", err)
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	ip := prefix.Addr().String()
	mask := prefixToMask(prefix)

	time.Sleep(50 * time.Millisecond)

	var setErr error
	for i := 0; i < 5; i++ {
		_, setErr = exec.Command("netsh", "interface", "ip", "set", "address",
			"name="+ifName, "static", ip, mask, "none").CombinedOutput()
		if setErr == nil {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if setErr != nil {
		session.End()
		adapter.Close()
		return nil, fmt.Errorf("netsh set address: %w", setErr)
	}

	_ = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		ifName, fmt.Sprintf("mtu=%d", mtu), "store=active").Run()

	dns := cfg.DNS
	if dns == "" {
		dns = "1.1.1.1"
	}
	_ = exec.Command("netsh", "interface", "ip", "set", "dns",
		"name="+ifName, "static", dns, "validate=no").Run()
	if cfg.SecondaryDNS != "" {
		_ = exec.Command("netsh", "interface", "ip", "add", "dns",
			"name="+ifName, cfg.SecondaryDNS, "index=2", "validate=no").Run()
	}
	_ = exec.Command("netsh", "interface", "ip", "set", "interface",
		ifName, "metric=1").Run()

	ifIdx := getInterfaceIndex(ifName)
	origGW, _ := getDefaultGateway()

	dev := &wintunDevice{
		adapter:  adapter,
		session:  session,
		readWait: session.ReadWaitEvent(),
		name:     ifName,
		mtu:      mtu,
		serverIP: cfg.ServerHost,
		origGW:   origGW,
		ifIndex:  ifIdx,
	}

	// Route configuration
	if origGW != "" && cfg.ServerHost != "" {
		_ = exec.Command("route", "add", cfg.ServerHost, "mask", "255.255.255.255", origGW).Run()
	}

	if ifIdx != "0" {
		_ = exec.Command("route", "add", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", ifIdx, "metric", "1").Run()
		_ = exec.Command("route", "add", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", ifIdx, "metric", "1").Run()
		_ = exec.Command("route", "add", dns, "mask", "255.255.255.255", "0.0.0.0", "if", ifIdx, "metric", "1").Run()
	}

	return dev, nil
}

func prefixToMask(p netip.Prefix) string {
	bits := p.Bits()
	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func getInterfaceIndex(name string) string {
	out, err := exec.Command("netsh", "interface", "ip", "show", "interface").Output()
	if err != nil {
		return "0"
	}
	for _, line := range splitLines(string(out)) {
		if strings.Contains(line, name) {
			fields := splitFields(line)
			if len(fields) >= 1 {
				return fields[0]
			}
		}
	}
	return "0"
}

func getDefaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	lines := splitLines(string(out))
	for _, line := range lines {
		fields := splitFields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := fields[2]
			if gw != "On-link" && gw != "0.0.0.0" {
				return gw, nil
			}
		}
	}
	return "", fmt.Errorf("no default gateway found")
}
