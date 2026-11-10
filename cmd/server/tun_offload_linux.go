//go:build linux

package main

import (
	"errors"
	"log"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// offloadTUN is a TUN device with IFF_VNET_HDR and TCP segmentation offloads, driven by the
// wireguard-go tun package, which splits GSO reads and merges writes with GRO.
type offloadTUN struct {
	dev   wgtun.Device
	iface string

	// Single-packet Read for callers that do not batch: a read can carry several packets, the
	// rest wait here.
	rmu    sync.Mutex
	rbufs  [][]byte
	rsizes []int
	rn, ri int
}

// openOffloadTUN creates iface with offloads. It fails on kernels or containers that refuse
// TUNSETOFFLOAD; the caller then opens a plain TUN.
func openOffloadTUN(iface string, mtu int) (*offloadTUN, error) {
	dev, err := wgtun.CreateTUN(iface, mtu)
	if err != nil {
		return nil, err
	}
	if dev.BatchSize() <= 1 {
		dev.Close()
		return nil, errors.New("TUN offloads unavailable")
	}
	go func() {
		for range dev.Events() { // link state events are not used; keep the channel drained
		}
	}()
	return &offloadTUN{dev: dev, iface: iface}, nil
}

func (t *offloadTUN) BatchSize() int { return t.dev.BatchSize() }

func (t *offloadTUN) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	return t.dev.Read(bufs, sizes, 0)
}

func (t *offloadTUN) WriteBatch(bufs [][]byte) (int, error) {
	return t.dev.Write(bufs, tunWriteHeadroom)
}

func (t *offloadTUN) Write(p []byte) (int, error) {
	bp := getTunWriteBuf()
	defer putTunWriteBuf(bp)
	if len(p) > len(*bp)-tunWriteHeadroom {
		return 0, errors.New("packet larger than the TUN write buffer")
	}
	n := copy((*bp)[tunWriteHeadroom:], p)
	if _, err := t.dev.Write([][]byte{(*bp)[:tunWriteHeadroom+n]}, tunWriteHeadroom); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (t *offloadTUN) Read(p []byte) (int, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	if t.ri >= t.rn {
		if t.rbufs == nil {
			t.rbufs = make([][]byte, t.dev.BatchSize())
			for i := range t.rbufs {
				t.rbufs[i] = make([]byte, 65535)
			}
			t.rsizes = make([]int, len(t.rbufs))
		}
		n, err := t.dev.Read(t.rbufs, t.rsizes, 0)
		if err != nil {
			return 0, err
		}
		t.rn, t.ri = n, 0
	}
	n := copy(p, t.rbufs[t.ri][:t.rsizes[t.ri]])
	t.ri++
	return n, nil
}

func (t *offloadTUN) Close() error {
	log.Printf("closing TUN %s", t.iface)
	return t.dev.Close()
}
