package main

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi                  = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardEntry = modIphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = modIphlpapi.NewProc("CreateIpForwardEntry2")
	procGetBestInterface         = modIphlpapi.NewProc("GetBestInterface")

	gatewayIfMu    sync.Mutex
	gatewayIfCache = map[string]uint32{}
)

// addRouteAPI adds an IPv4 route through the IP Helper API. It returns in
// microseconds, while route.exe costs a process spawn per call. That matters
// because split-tunnel routes are added on the TUN write path: a burst of
// route.exe calls there froze all downstream traffic for seconds.
// ifIndex 0 means "the interface that reaches gateway".
func addRouteAPI(dest, mask, gateway string, ifIndex uint32) error {
	d := net.ParseIP(dest).To4()
	m := net.ParseIP(mask).To4()
	if d == nil || m == nil {
		return fmt.Errorf("bad route %s/%s", dest, mask)
	}
	ones, bits := net.IPMask(m).Size()
	if bits != 32 {
		return fmt.Errorf("non-contiguous mask %s", mask)
	}
	var gw net.IP
	if gateway != "" {
		if gw = net.ParseIP(gateway).To4(); gw == nil {
			return fmt.Errorf("bad gateway %s", gateway)
		}
	}
	if ifIndex == 0 {
		if gw == nil {
			return fmt.Errorf("no interface for route %s/%s", dest, mask)
		}
		idx, err := gatewayInterface(gateway, gw)
		if err != nil {
			return err
		}
		ifIndex = idx
	}

	var row windows.MibIpForwardRow2
	if err := procInitializeIpForwardEntry.Find(); err != nil {
		return err
	}
	procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = ifIndex
	row.DestinationPrefix.PrefixLength = uint8(ones)
	setSockaddr4(&row.DestinationPrefix.Prefix, d)
	setSockaddr4(&row.NextHop, gw)
	row.Metric = 1
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Origin = windows.NlroManual

	r, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 && windows.Errno(r) != windows.ERROR_OBJECT_ALREADY_EXISTS {
		return windows.Errno(r)
	}
	return nil
}

func setSockaddr4(sa *windows.RawSockaddrInet, ip net.IP) {
	sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa))
	sa4.Family = windows.AF_INET
	if ip != nil {
		copy(sa4.Addr[:], ip)
	}
}

// gatewayInterface finds the interface that reaches gateway, the way
// "route add ... <gateway>" picks it. The gateway is on-link, so the TUN's
// 0/1 and 128/1 routes never win here. Cached because origGW does not change.
func gatewayInterface(key string, gw net.IP) (uint32, error) {
	gatewayIfMu.Lock()
	defer gatewayIfMu.Unlock()
	if idx, ok := gatewayIfCache[key]; ok {
		return idx, nil
	}
	if err := procGetBestInterface.Find(); err != nil {
		return 0, err
	}
	var idx uint32
	// IPAddr is the address in network byte order, read as a native uint32.
	addr := *(*uint32)(unsafe.Pointer(&gw[0]))
	r, _, _ := procGetBestInterface.Call(uintptr(addr), uintptr(unsafe.Pointer(&idx)))
	if r != 0 {
		return 0, windows.Errno(r)
	}
	gatewayIfCache[key] = idx
	return idx, nil
}
