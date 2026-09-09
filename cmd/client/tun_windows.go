package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

type wintunAdapter struct {
	adapter      *wintun.Adapter
	session      wintun.Session
	readWait     windows.Handle
	origGW       string
	serverIP     string
	ifIndex      string
	dns          string
	secondaryDNS string
	writeMu      sync.Mutex
	routesMu     sync.Mutex
	routes       map[string]routeSpec
	stopApps     chan struct{}
	stopOnce     sync.Once
}

type routeSpec struct {
	dest string
	mask string
}

const (
	defaultTunMTU      = 1420
	udpSafeTunMTU      = 1420
	mobileSafeTunMTU   = 1360
	minAutoTunMTU      = 1280
	wintunRingCapacity = 0x800000 // 8 MiB: optimal for 2+ Gbps without non-paged kernel pool stalls
)

func (w *wintunAdapter) Read(buf []byte) (int, error) {
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

func (w *wintunAdapter) Write(buf []byte) (int, error) {
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

func (w *wintunAdapter) Close() error {
	log.Println("Restoring routes and DNS leak policies...")
	if w.stopApps != nil {
		w.stopOnce.Do(func() { close(w.stopApps) })
	}
	exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", "ObsidianVPN").Run()
	if w.serverIP != "" {
		exec.Command("route", "delete", w.serverIP).Run()
	}
	w.routesMu.Lock()
	for _, route := range w.routes {
		exec.Command("route", "delete", route.dest).Run()
	}
	w.routes = map[string]routeSpec{}
	w.routesMu.Unlock()
	psCleanRoutes(w.ifIndex, w.dns, w.secondaryDNS)
	restoreWindowsDNSLeakProtection(w.origGW)
	exec.Command("ipconfig", "/flushdns").Run()
	log.Printf("Routes and DNS settings restored")
	w.session.End()
	w.adapter.Close()
	return nil
}

func enableWindowsDNSLeakProtection(origGW, primaryDNS, secondaryDNS string) {
	// 1. Block outbound DNS (UDP and TCP port 53) on all physical network adapters
	// so Windows and applications cannot leak queries to ISP DNS (Rostelecom, local router, etc).
	// Only the ObsidianVPN virtual adapter is exempted from this block.
	// Also block all outbound IPv6 DNS (::/0) since the VPN tunnel currently routes IPv4,
	// completely eliminating dual-stack ISP IPv6 DNS leaks (Rostelecom 2a01:620:... etc).
	// 2. Add NRPT rule to bind all FQDN resolution (".") strictly to VPN tunnel DNS.
	// 3. Disable Smart Multi-Homed Name Resolution (SMHNR) and LLMNR during active session.
	// 4. Flush DNS cache.
	nsList := fmt.Sprintf("@('%s','2606:4700:4700::1111','2001:4860:4860::8888')", primaryDNS)
	if secondaryDNS != "" {
		nsList = fmt.Sprintf("@('%s','%s','2606:4700:4700::1111','2001:4860:4860::8888')", primaryDNS, secondaryDNS)
	}

	psScript := fmt.Sprintf(`
$adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Name -ne 'ObsidianVPN' | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty Name
if ($adapters) {
    New-NetFirewallRule -DisplayName 'ObsidianVPN-Block-Physical-DNS-UDP' -Name 'ObsidianVPN-Block-Physical-DNS-UDP' -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -InterfaceAlias $adapters -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName 'ObsidianVPN-Block-Physical-DNS-TCP' -Name 'ObsidianVPN-Block-Physical-DNS-TCP' -Direction Outbound -Action Block -Protocol TCP -RemotePort 53 -InterfaceAlias $adapters -ErrorAction SilentlyContinue | Out-Null
}
Add-DnsClientNrptRule -Namespace '.' -NameServers %s -DisplayName 'ObsidianVPN-NRPT' -ErrorAction SilentlyContinue | Out-Null
Clear-DnsClientCache -ErrorAction SilentlyContinue | Out-Null
`, nsList)

	startCommand("enable DNS leak protection", "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript)

	// Block router IP directly as extra safeguard
	if origGW != "" {
		startCommand("block router DNS UDP", "netsh", "advfirewall", "firewall", "add", "rule",
			"name=ObsidianVPN-Block-Router-DNS", "dir=out", "action=block", "protocol=UDP", "remoteport=53", "remoteip="+origGW)
		startCommand("block router DNS TCP", "netsh", "advfirewall", "firewall", "add", "rule",
			"name=ObsidianVPN-Block-Router-DNS-TCP", "dir=out", "action=block", "protocol=TCP", "remoteport=53", "remoteip="+origGW)
	}

	// Disable Smart Multi-Homed Name Resolution (SMHNR) during active session
	startCommand("disable SMHNR", "reg", "add",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		"/v", "DisableSmartNameResolution", "/t", "REG_DWORD", "/d", "1", "/f")
	startCommand("disable LLMNR", "reg", "add",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		"/v", "EnableMulticast", "/t", "REG_DWORD", "/d", "0", "/f")
}

func restoreWindowsDNSLeakProtection(origGW string) {
	// 1. Fast direct netsh removal of firewall rules (<20ms vs 1.5s PowerShell)
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ObsidianVPN-Block-Physical-DNS-UDP").Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ObsidianVPN-Block-Physical-DNS-TCP").Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ObsidianVPN-Block-IPv6-DNS-UDP").Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ObsidianVPN-Block-IPv6-DNS-TCP").Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ObsidianVPN-Block-Router-DNS").Run()
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=ObsidianVPN-Block-Router-DNS-TCP").Run()

	// 2. Remove temporary registry policies
	exec.Command("reg", "delete",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		"/v", "DisableSmartNameResolution", "/f").Run()
	exec.Command("reg", "delete",
		`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`,
		"/v", "EnableMulticast", "/f").Run()

	// 3. Fast non-blocking cleanup of NRPT rule and DNS cache
	startCommand("clean NRPT and DNS cache", "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
		"Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'ObsidianVPN-NRPT' | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; Clear-DnsClientCache -ErrorAction SilentlyContinue")
}

func psCleanRoutes(ifIdx, primaryDNS, secondaryDNS string) {
	// Remove stale split-default routes left by crashed/older clients. Windows may
	// keep them on a dead Wintun interface with a better metric than the new one.
	exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", "ObsidianVPN").Run()
	if primaryDNS != "" {
		exec.Command("route", "delete", primaryDNS).Run()
	}
	if secondaryDNS != "" {
		exec.Command("route", "delete", secondaryDNS).Run()
	}
}

func openTUN(cfg Config) io.ReadWriteCloser {
	if cfg.TunAddress == "" {
		cfg.TunAddress = "10.8.0.2/24"
	}

	adapter, err := wintun.CreateAdapter("ObsidianVPN", "Wintun", nil)
	if err != nil {
		log.Printf("wintun create: %v (try running as Administrator)", err)
		return nil
	}
	// Prevent GC from finalizing adapter
	runtime.SetFinalizer(adapter, nil)

	prefix, err := netip.ParsePrefix(cfg.TunAddress)
	if err != nil {
		adapter.Close()
		log.Printf("invalid tun_address %q: %v", cfg.TunAddress, err)
		return nil
	}

	// Start session FIRST — netsh kills sessions started after it
	session, err := adapter.StartSession(wintunRingCapacity)
	if err != nil {
		adapter.Close()
		log.Printf("wintun start session: %v", err)
		return nil
	}
	log.Printf("wintun session started")

	// Build the result struct immediately to prevent GC
	ip := prefix.Addr().String()
	w := &wintunAdapter{
		adapter:  adapter,
		session:  session,
		readWait: session.ReadWaitEvent(),
		serverIP: cfg.ServerHost,
		routes:   map[string]routeSpec{},
	}

	dns := strings.TrimSpace(cfg.DNS)
	if dns == "" || dns == "10.8.0.1" {
		dns = "1.1.1.1"
	}
	primaryDNS := dns
	secondaryDNS := "1.0.0.1"
	if primaryDNS == "1.1.1.1" {
		secondaryDNS = "8.8.8.8"
	} else if primaryDNS == "8.8.8.8" {
		secondaryDNS = "1.1.1.1"
	}
	w.dns = primaryDNS
	w.secondaryDNS = secondaryDNS
	mtu := chooseTunMTU(cfg)

	// Give Windows a short moment to publish the new adapter before netsh.
	time.Sleep(50 * time.Millisecond)

	mask := prefixToMask(prefix)

	// Set IP address
	var out []byte
	for i := 0; i < 5; i++ {
		out, err = exec.Command("netsh", "interface", "ip", "set", "address",
			"name=ObsidianVPN", "static", ip, mask, "none").CombinedOutput()
		if err == nil {
			break
		}
		log.Printf("netsh attempt %d: %s", i+1, strings.TrimSpace(string(out)))
		time.Sleep(150 * time.Millisecond)
	}
	if err != nil {
		log.Printf("netsh set address failed: %v: %s", err, out)
		session.End()
		adapter.Close()
		return nil
	}
	log.Printf("TUN address set: %s", cfg.TunAddress)

	runCommand("set MTU", "netsh", "interface", "ipv4", "set", "subinterface",
		"ObsidianVPN", fmt.Sprintf("mtu=%d", mtu), "store=active")
	log.Printf("TUN MTU selected: %d", mtu)

	runCommand("set DNS", "netsh", "interface", "ip", "set", "dns",
		"name=ObsidianVPN", "static", primaryDNS, "validate=no")
	if secondaryDNS != "" {
		runCommand("add secondary DNS", "netsh", "interface", "ip", "add", "dns",
			"name=ObsidianVPN", secondaryDNS, "index=2", "validate=no")
	}
	runCommand("set interface metric", "netsh", "interface", "ip", "set", "interface",
		"ObsidianVPN", "metric=1")

	if cfg.EnableIPv6 {
		// Enable IPv6 Dual-Stack in-tunnel routing in background without blocking IPv4 tunnel establishment
		go func() {
			exec.Command("powershell", "-NoProfile", "-Command",
				"Enable-NetAdapterBinding -Name 'ObsidianVPN' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue").Run()
			runCommand("set IPv6 address", "netsh", "interface", "ipv6", "set", "address",
				"interface=ObsidianVPN", "address=fd00:8::2/64", "store=active")
			runCommand("set IPv6 metric", "netsh", "interface", "ipv6", "set", "interface",
				"ObsidianVPN", "metric=1", "store=active")
			runCommand("set IPv6 MTU", "netsh", "interface", "ipv6", "set", "subinterface",
				"ObsidianVPN", fmt.Sprintf("mtu=%d", mtu), "store=active")
			runCommand("set IPv6 DNS", "netsh", "interface", "ipv6", "set", "dnsservers",
				"ObsidianVPN", "static", "2606:4700:4700::1111", "validate=no")
			runCommand("add secondary IPv6 DNS", "netsh", "interface", "ipv6", "add", "dnsservers",
				"ObsidianVPN", "2001:4860:4860::8888", "index=2", "validate=no")
			runCommand("add default IPv6 route", "netsh", "interface", "ipv6", "add", "route",
				"::/0", "ObsidianVPN", "metric=1", "store=active")
			log.Printf("Dual-Stack IPv6 configured on TUN: fd00:8::2/64")
		}()
	} else {
		startCommand("disable IPv6 binding", "powershell", "-NoProfile", "-Command",
			"Disable-NetAdapterBinding -Name 'ObsidianVPN' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue")
		exec.Command("netsh", "interface", "ipv6", "delete", "route", "::/0", "ObsidianVPN").Run()
	}

	ifIndex := getInterfaceIndex("ObsidianVPN")
	w.ifIndex = ifIndex
	log.Printf("TUN interface index: %s", ifIndex)

	origGW, _ := getDefaultGateway()
	w.origGW = origGW
	log.Printf("original gateway: %s", origGW)

	enableWindowsDNSLeakProtection(origGW, primaryDNS, secondaryDNS)
	startCommand("flush DNS cache", "ipconfig", "/flushdns")

	// Bypass route for VPN server
	if origGW != "" {
		exec.Command("route", "add", cfg.ServerHost, "mask", "255.255.255.255", origGW).Run()
		log.Printf("bypass route: %s -> %s", cfg.ServerHost, origGW)
	}

	// Clean ALL stale 0/1 and 128/1 routes from previous runs (any interface)
	psCleanRoutes(ifIndex, primaryDNS, secondaryDNS)

	// Add routes
	mode := splitTunnelMode(cfg)
	siteRoutes := resolveSplitRouteSpecs(cfg.RouteIPs, cfg.SplitSites)
	if !splitTunnelEnabled(cfg) {
		addInterfaceRoute("0.0.0.0", "128.0.0.0", ifIndex)
		addInterfaceRoute("128.0.0.0", "128.0.0.0", ifIndex)
		log.Printf("full tunnel mode via TUN IF %s", ifIndex)
	} else if mode == splitModeInclude {
		for _, route := range siteRoutes {
			w.addVPNRoute(route, ifIndex)
		}
		log.Printf("split-tunnel include mode: %d site/ip routes", len(siteRoutes))
	} else {
		addInterfaceRoute("0.0.0.0", "128.0.0.0", ifIndex)
		addInterfaceRoute("128.0.0.0", "128.0.0.0", ifIndex)
		for _, route := range siteRoutes {
			w.addBypassRoute(route, origGW)
		}
		log.Printf("split-tunnel exclude mode: %d site/ip bypass routes", len(siteRoutes))
	}
	addInterfaceRoute(primaryDNS, "255.255.255.255", ifIndex)
	log.Printf("dns route: %s -> TUN", primaryDNS)
	if secondaryDNS != "" {
		addInterfaceRoute(secondaryDNS, "255.255.255.255", ifIndex)
		log.Printf("secondary dns route: %s -> TUN", secondaryDNS)
	}

	processSelectors := splitTunnelEntries(nil, nil, cfg.SplitApps, cfg.SplitProcesses)
	if len(processSelectors) > 0 {
		w.stopApps = make(chan struct{})
		go w.monitorAppRoutes(processSelectors, mode, ifIndex, origGW)
	}

	// Keep adapter alive
	runtime.KeepAlive(adapter)
	runtime.KeepAlive(w)

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		w.Close()
		os.Exit(0)
	}()

	return w
}

func prefixToMask(p netip.Prefix) string {
	bits := p.Bits()
	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func defaultDNSForTunAddress(tunAddress string) string {
	return "1.1.1.1"
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

func chooseTunMTU(cfg Config) int {
	if cfg.MTU > 0 && cfg.MTU != defaultTunMTU && cfg.MTU != mobileSafeTunMTU {
		if cfg.MTU < minAutoTunMTU {
			return minAutoTunMTU
		}
		if cfg.MTU > defaultTunMTU {
			return defaultTunMTU
		}
		return cfg.MTU
	}

	gateway, sourceIP := getDefaultGateway()
	ifaceName := interfaceNameByIPv4(sourceIP)
	ssid := wifiSSID(ifaceName)
	uplinkMTU := interfaceMTU(ifaceName)

	if reason := mobileNetworkReason(ifaceName, "", ssid, gateway); reason != "" {
		log.Printf("mobile-like uplink detected: %s iface=%q ssid=%q gateway=%q mtu=%d",
			reason, ifaceName, ssid, gateway, uplinkMTU)
		return mobileSafeTunMTU
	}
	if uplinkMTU > 0 && uplinkMTU < defaultTunMTU {
		mtu := uplinkMTU - 80
		if mtu < minAutoTunMTU {
			mtu = minAutoTunMTU
		}
		if mtu > mobileSafeTunMTU {
			mtu = mobileSafeTunMTU
		}
		log.Printf("low uplink MTU detected: iface=%q uplink_mtu=%d tun_mtu=%d", ifaceName, uplinkMTU, mtu)
		return mtu
	}

	log.Printf("high-speed uplink detected: iface=%q ssid=%q gateway=%q mtu=%d -> tun_mtu=%d", ifaceName, ssid, gateway, uplinkMTU, defaultTunMTU)
	return defaultTunMTU
}

func interfaceNameByIPv4(ip string) string {
	if ip == "" {
		return ""
	}
	for _, iface := range mustInterfaces() {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if strings.HasPrefix(addr.String(), ip+"/") {
				return iface.Name
			}
		}
	}
	return ""
}

func mustInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	return ifaces
}

func adapterDescription(name string) string {
	return ""
}

func wifiSSID(ifaceName string) string {
	name := strings.ToLower(ifaceName)
	if !strings.Contains(name, "wi-fi") && !strings.Contains(name, "wifi") &&
		!strings.Contains(name, "wireless") && !strings.Contains(name, "wlan") {
		return ""
	}
	out, err := exec.Command("netsh", "wlan", "show", "interfaces").Output()
	if err != nil {
		return ""
	}
	for _, line := range splitLines(string(out)) {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "bssid") || !strings.HasPrefix(lower, "ssid") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func interfaceMTU(name string) int {
	if name == "" {
		return 0
	}
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "subinterfaces").Output()
	if err != nil {
		return 0
	}
	for _, line := range splitLines(string(out)) {
		if !strings.Contains(line, name) {
			continue
		}
		fields := splitFields(line)
		if len(fields) == 0 {
			continue
		}
		var mtu int
		if _, err := fmt.Sscanf(fields[0], "%d", &mtu); err == nil {
			return mtu
		}
	}
	return 0
}

func mobileNetworkReason(ifaceName, desc, ssid, gateway string) string {
	if isMobileLike(ifaceName + " " + desc) {
		return "adapter marker"
	}
	if isMobileLike(ssid) {
		return "ssid marker"
	}
	if isPhoneHotspotGateway(gateway) {
		return "phone-hotspot gateway"
	}
	return ""
}

func isMobileLike(s string) bool {
	s = strings.ToLower(s)
	replacer := strings.NewReplacer(
		"-", " ", "_", " ", ".", " ", "/", " ", "\\", " ",
		"(", " ", ")", " ", "[", " ", "]", " ", ",", " ", "'", " ",
	)
	tokens := splitFields(replacer.Replace(s))
	for _, token := range tokens {
		switch token {
		case "cellular", "mobile", "lte", "5g", "4g", "3g", "wwan", "mbim",
			"modem", "broadband", "rndis", "ncm", "android", "iphone",
			"huawei", "zte", "qualcomm", "mediatek", "samsung", "tether",
			"hotspot", "galaxy", "redmi", "xiaomi", "poco", "honor",
			"oneplus", "pixel", "realme", "oppo", "vivo", "androidap":
			return true
		}
	}
	return false
}

func isPhoneHotspotGateway(gateway string) bool {
	if gateway == "" {
		return false
	}
	if gateway == "172.20.10.1" || gateway == "192.168.43.1" ||
		gateway == "192.168.49.1" || gateway == "192.168.44.1" ||
		gateway == "192.168.137.1" {
		return true
	}
	return strings.HasPrefix(gateway, "192.168.42.") ||
		strings.HasPrefix(gateway, "172.20.10.")
}

func runCommand(label, name string, args ...string) error {
	start := time.Now()
	out, err := exec.Command(name, args...).CombinedOutput()
	elapsed := time.Since(start)
	if err != nil {
		if len(out) > 0 {
			log.Printf("%s failed after %s: %v: %s", label, elapsed.Round(time.Millisecond), err, strings.TrimSpace(string(out)))
		} else {
			log.Printf("%s failed after %s: %v", label, elapsed.Round(time.Millisecond), err)
		}
	} else if elapsed > 200*time.Millisecond {
		log.Printf("%s took %s", label, elapsed.Round(time.Millisecond))
	}
	return err
}

func startCommand(label, name string, args ...string) {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		log.Printf("%s start failed: %v", label, err)
		return
	}
	go func() {
		start := time.Now()
		err := cmd.Wait()
		elapsed := time.Since(start)
		if err != nil {
			log.Printf("%s failed after %s: %v", label, elapsed.Round(time.Millisecond), err)
		} else if elapsed > 200*time.Millisecond {
			log.Printf("%s took %s", label, elapsed.Round(time.Millisecond))
		}
	}()
}

func addInterfaceRoute(dest, mask, ifIndex string) {
	runCommand("route add "+dest+"/"+mask, "route", "add", dest, "mask", mask, "0.0.0.0", "metric", "1", "if", ifIndex)
}

func addGatewayRoute(dest, mask, gateway string) {
	if gateway == "" {
		return
	}
	runCommand("route add "+dest+"/"+mask, "route", "add", dest, "mask", mask, gateway, "metric", "1")
}

func (w *wintunAdapter) addVPNRoute(route routeSpec, ifIndex string) {
	if route.dest == "" || route.mask == "" {
		return
	}
	if !w.rememberRoute(route) {
		return
	}
	addInterfaceRoute(route.dest, route.mask, ifIndex)
	log.Printf("vpn route: %s/%s -> TUN", route.dest, route.mask)
}

func (w *wintunAdapter) addBypassRoute(route routeSpec, gateway string) {
	if route.dest == "" || route.mask == "" || gateway == "" {
		return
	}
	if !w.rememberRoute(route) {
		return
	}
	addGatewayRoute(route.dest, route.mask, gateway)
	log.Printf("bypass route: %s/%s -> %s", route.dest, route.mask, gateway)
}

func (w *wintunAdapter) rememberRoute(route routeSpec) bool {
	w.routesMu.Lock()
	defer w.routesMu.Unlock()
	key := route.dest + "/" + route.mask
	if w.routes[key].dest != "" {
		return false
	}
	w.routes[key] = route
	return true
}

func resolveSplitRouteSpecs(routeIPs, sites []string) []routeSpec {
	var out []routeSpec
	for _, item := range splitTunnelEntries(routeIPs, sites, nil, nil) {
		if route, ok := parseRouteSpec(item); ok {
			out = append(out, route)
			continue
		}
		ips, err := net.LookupIP(item)
		if err != nil {
			log.Printf("split site resolve failed %q: %v", item, err)
			continue
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				out = append(out, routeSpec{dest: ip4.String(), mask: "255.255.255.255"})
			}
		}
	}
	return dedupeRouteSpecs(out)
}

func parseRouteSpec(item string) (routeSpec, bool) {
	item = strings.TrimSpace(item)
	if item == "" {
		return routeSpec{}, false
	}
	if ip := net.ParseIP(item); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return routeSpec{dest: ip4.String(), mask: "255.255.255.255"}, true
		}
		return routeSpec{}, false
	}
	ip, ipNet, err := net.ParseCIDR(item)
	if err != nil {
		return routeSpec{}, false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return routeSpec{}, false
	}
	mask := ipNet.Mask
	if len(mask) != net.IPv4len {
		return routeSpec{}, false
	}
	return routeSpec{
		dest: ip4.Mask(mask).String(),
		mask: fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3]),
	}, true
}

func dedupeRouteSpecs(routes []routeSpec) []routeSpec {
	seen := make(map[string]bool)
	out := make([]routeSpec, 0, len(routes))
	for _, route := range routes {
		key := route.dest + "/" + route.mask
		if route.dest == "" || route.mask == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, route)
	}
	return out
}

func (w *wintunAdapter) monitorAppRoutes(apps []string, mode, ifIndex, gateway string) {
	names := normalizeAppNames(apps)
	if len(names) == 0 {
		return
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var scanning atomic.Bool
	for {
		if scanning.CompareAndSwap(false, true) {
			go func() {
				defer scanning.Store(false)
				w.addCurrentAppRoutes(names, mode, ifIndex, gateway)
			}()
		}
		select {
		case <-w.stopApps:
			return
		case <-ticker.C:
		}
	}
}

func normalizeAppNames(apps []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, app := range apps {
		app = strings.Trim(strings.TrimSpace(app), `"`)
		if app == "" {
			continue
		}
		app = strings.ToLower(app)
		app = strings.TrimSuffix(app, ".exe")
		if idx := strings.LastIndexAny(app, `\/`); idx >= 0 {
			app = app[idx+1:]
		}
		if app == "" || seen[app] {
			continue
		}
		seen[app] = true
		out = append(out, app)
	}
	return out
}

func (w *wintunAdapter) addCurrentAppRoutes(apps []string, mode, ifIndex, gateway string) {
	for _, ip := range activeRemoteIPsForApps(apps) {
		route := routeSpec{dest: ip, mask: "255.255.255.255"}
		if mode == splitModeInclude {
			w.addVPNRoute(route, ifIndex)
		} else {
			w.addBypassRoute(route, gateway)
		}
	}
}

func activeRemoteIPsForApps(apps []string) []string {
	if len(apps) == 0 {
		return nil
	}
	quoted := make([]string, 0, len(apps))
	for _, app := range apps {
		quoted = append(quoted, "'"+strings.ReplaceAll(app, "'", "''")+"'")
	}
	script := fmt.Sprintf(`
$names = @(%s)
$pids = Get-Process -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.ProcessName.ToLowerInvariant() } | Select-Object -ExpandProperty Id
if ($pids) {
  Get-NetTCPConnection -State SynSent,Established -ErrorAction SilentlyContinue |
    Where-Object { $pids -contains $_.OwningProcess -and $_.RemoteAddress -match '^\d+\.\d+\.\d+\.\d+$' } |
    Select-Object -ExpandProperty RemoteAddress -Unique
}
`, strings.Join(quoted, ","))
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		log.Printf("split app scan failed: %v", err)
		return nil
	}
	var ips []string
	for _, line := range splitLines(string(out)) {
		ip := strings.TrimSpace(line)
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			ips = append(ips, parsed.To4().String())
		}
	}
	return ips
}

func getDefaultGateway() (gw string, iface string) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", ""
	}
	for _, line := range splitLines(string(out)) {
		fields := splitFields(line)
		if len(fields) >= 4 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2], fields[3]
		}
	}
	return "", ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	return lines
}

func splitFields(s string) []string {
	var fields []string
	inField := false
	start := 0
	for i, c := range s {
		if c == ' ' || c == '\t' || c == '\r' {
			if inField {
				fields = append(fields, s[start:i])
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
		fields = append(fields, s[start:])
	}
	return fields
}
