//go:build cgo

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef int (*socket_protect_fn)(int fd);
typedef void (*status_cb_fn)(const char* status, const char* detail);
typedef void (*stats_cb_fn)(int64_t bytes_sent, int64_t bytes_recv, int64_t tx_speed, int64_t rx_speed);

static inline int call_socket_protect(socket_protect_fn fn, int fd) {
    if (!fn) return 1;
    return fn(fd);
}

static inline void call_status_cb(status_cb_fn fn, const char* status, const char* detail) {
    if (fn) fn(status, detail);
}

static inline void call_stats_cb(stats_cb_fn fn, int64_t bs, int64_t br, int64_t tx, int64_t rx) {
    if (fn) fn(bs, br, tx, rx);
}
*/
import "C"

import (
	"unsafe"

	"obsidian/pkg/mobile"
)

type cgoProtector struct {
	fn C.socket_protect_fn
}

func (p *cgoProtector) Protect(fd int) bool {
	if p.fn == nil {
		return true
	}
	return C.call_socket_protect(p.fn, C.int(fd)) != 0
}

type cgoStatusListener struct {
	fn C.status_cb_fn
}

func (l *cgoStatusListener) OnStatusChange(status, detail string) {
	if l.fn == nil {
		return
	}
	cStatus := C.CString(status)
	cDetail := C.CString(detail)
	defer C.free(unsafe.Pointer(cStatus))
	defer C.free(unsafe.Pointer(cDetail))
	C.call_status_cb(l.fn, cStatus, cDetail)
}

type cgoStatsListener struct {
	fn C.stats_cb_fn
}

func (l *cgoStatsListener) OnStats(bytesSent, bytesRecv, txSpeed, rxSpeed int64) {
	if l.fn == nil {
		return
	}
	C.call_stats_cb(l.fn, C.int64_t(bytesSent), C.int64_t(bytesRecv), C.int64_t(txSpeed), C.int64_t(rxSpeed))
}

//export ObsidianStartTunnelWithFd
func ObsidianStartTunnelWithFd(
	cURI *C.char,
	tunFd C.int,
	mtu C.int,
	protectFn C.socket_protect_fn,
	statusFn C.status_cb_fn,
	statsFn C.stats_cb_fn,
) *C.char {
	uri := C.GoString(cURI)
	var protector mobile.SocketProtector
	if protectFn != nil {
		protector = &cgoProtector{fn: protectFn}
	}
	var statusListener mobile.StatusListener
	if statusFn != nil {
		statusListener = &cgoStatusListener{fn: statusFn}
	}
	var statsListener mobile.StatsListener
	if statsFn != nil {
		statsListener = &cgoStatsListener{fn: statsFn}
	}

	id, err := mobile.StartTunnelWithFd(uri, int(tunFd), int(mtu), protector, statusListener, statsListener)
	if err != nil {
		return nil
	}
	return C.CString(id)
}

//export ObsidianStartPacketTunnel
func ObsidianStartPacketTunnel(
	cURI *C.char,
	mtu C.int,
	protectFn C.socket_protect_fn,
	statusFn C.status_cb_fn,
	statsFn C.stats_cb_fn,
) *C.char {
	uri := C.GoString(cURI)
	var protector mobile.SocketProtector
	if protectFn != nil {
		protector = &cgoProtector{fn: protectFn}
	}
	var statusListener mobile.StatusListener
	if statusFn != nil {
		statusListener = &cgoStatusListener{fn: statusFn}
	}
	var statsListener mobile.StatsListener
	if statsFn != nil {
		statsListener = &cgoStatsListener{fn: statsFn}
	}

	id, err := mobile.StartPacketTunnel(uri, int(mtu), protector, statusListener, statsListener)
	if err != nil {
		return nil
	}
	return C.CString(id)
}

//export ObsidianInjectPacket
func ObsidianInjectPacket(cSessionID *C.char, data *C.char, length C.int) C.int {
	sessID := C.GoString(cSessionID)
	pkt := C.GoBytes(unsafe.Pointer(data), length)
	if err := mobile.InjectPacket(sessID, pkt); err != nil {
		return -1
	}
	return 0
}

//export ObsidianStopTunnel
func ObsidianStopTunnel(cSessionID *C.char) C.int {
	sessID := C.GoString(cSessionID)
	if err := mobile.StopTunnel(sessID); err != nil {
		return -1
	}
	return 0
}

//export ObsidianStartLocalProxy
func ObsidianStartLocalProxy(cListenAddr *C.char) C.int {
	addr := C.GoString(cListenAddr)
	if err := mobile.StartLocalProxy(addr); err != nil {
		return -1
	}
	return 0
}

//export ObsidianStopLocalProxy
func ObsidianStopLocalProxy() C.int {
	if err := mobile.StopLocalProxy(); err != nil {
		return -1
	}
	return 0
}

//export ObsidianParseURI
func ObsidianParseURI(cURI *C.char) *C.char {
	uri := C.GoString(cURI)
	jsonOut, err := mobile.ParseConfigURI(uri)
	if err != nil {
		return nil
	}
	return C.CString(jsonOut)
}

//export ObsidianFreeString
func ObsidianFreeString(str *C.char) {
	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

func main() {}
