// Command caph drives the real client engine through a scripted inner traffic pattern so the
// outer traffic of two core versions can be captured and compared. Linux only test tool.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"obsidian/obsidian"
	"obsidian/obsidian/client"
)

type dev struct {
	in     chan []byte
	closed chan struct{}
	once   sync.Once
	rx     atomic.Int64
	rxB    atomic.Int64
}

func (d *dev) Read(b []byte) (int, error) {
	select {
	case p := <-d.in:
		return copy(b, p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}
func (d *dev) Write(p []byte) (int, error) { d.rx.Add(1); d.rxB.Add(int64(len(p))); return len(p), nil }
func (d *dev) Close() error                { d.once.Do(func() { close(d.closed) }); return nil }

var src = [4]byte{10, 8, 0, 2}
var dst = [4]byte{10, 8, 0, 1}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func ipv4(proto byte, payload []byte, id uint16) []byte {
	p := make([]byte, 20+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], id)
	p[8] = 64
	p[9] = proto
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[10:], csum(p[:20]))
	copy(p[20:], payload)
	return p
}

func icmpEcho(seq uint16, size int) []byte {
	b := make([]byte, 8+size)
	b[0] = 8
	binary.BigEndian.PutUint16(b[4:], 0x4242)
	binary.BigEndian.PutUint16(b[6:], seq)
	for i := 8; i < len(b); i++ {
		b[i] = byte(i)
	}
	binary.BigEndian.PutUint16(b[2:], csum(b))
	return ipv4(1, b, seq)
}

// tlsHello is a TCP PSH/ACK segment to port 443 whose payload starts like a ClientHello.
func tlsHello(port uint16, size int) []byte {
	pl := make([]byte, size)
	pl[0], pl[1], pl[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(pl[3:], uint16(size-5))
	pl[5] = 0x01
	for i := 6; i < size; i++ {
		pl[i] = byte(i * 7)
	}
	tcp := make([]byte, 20+size)
	binary.BigEndian.PutUint16(tcp[0:], port)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 1000)
	binary.BigEndian.PutUint32(tcp[8:], 1)
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[20:], pl)
	ph := make([]byte, 12+len(tcp))
	copy(ph[0:4], src[:])
	copy(ph[4:8], dst[:])
	ph[9] = 6
	binary.BigEndian.PutUint16(ph[10:], uint16(len(tcp)))
	copy(ph[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:], csum(ph))
	return ipv4(6, tcp, port)
}

func mark(name string) { fmt.Printf("PHASE %s %d\n", name, time.Now().UnixNano()) }

func main() {
	f, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var cfg obsidian.ClientConfig
	if err := json.Unmarshal(f, &cfg); err != nil {
		log.Fatal(err)
	}
	s, err := client.NewSession(&cfg, client.WithAutoReconnect(false),
		client.WithStatusCallback(func(st, detail string) { log.Printf("status %s: %s", st, detail) }))
	if err != nil {
		log.Fatal(err)
	}
	// CAPH_TUN=name runs the session on a real TUN device until SIGINT/SIGTERM, so real TCP
	// tools (iperf3, curl) can be driven through it. The caller assigns the address and routes.
	if name := os.Getenv("CAPH_TUN"); name != "" {
		tun, err := openTUN(name)
		if err != nil {
			log.Fatal(err)
		}
		s.StartAsync(tun)
		deadline := time.Now().Add(20 * time.Second)
		for s.Status() != client.StatusConnected {
			if time.Now().After(deadline) {
				log.Fatalf("not connected: %s", s.Status())
			}
			time.Sleep(50 * time.Millisecond)
		}
		mark("connected")
		if path := os.Getenv("CAPH_CPUPROFILE"); path != "" {
			f, err := os.Create(path)
			if err != nil {
				log.Fatal(err)
			}
			_ = pprof.StartCPUProfile(f)
			defer func() { pprof.StopCPUProfile(); f.Close() }()
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		s.Stop()
		tun.Close()
		return
	}
	d := &dev{in: make(chan []byte, 4096), closed: make(chan struct{})}
	s.StartAsync(d)
	deadline := time.Now().Add(20 * time.Second)
	for s.Status() != client.StatusConnected {
		if time.Now().After(deadline) {
			log.Fatalf("not connected: %s", s.Status())
		}
		time.Sleep(50 * time.Millisecond)
	}
	mark("connected")
	if os.Getenv("CAPH_CONNECT_ONLY") != "" {
		s.Stop()
		d.Close()
		return
	}
	time.Sleep(2 * time.Second)

	mark("tls")
	for i := 0; i < 20; i++ {
		d.in <- tlsHello(uint16(40000+i), 517)
		time.Sleep(200 * time.Millisecond)
	}
	mark("small")
	seq := uint16(0)
	for b := 0; b < 10; b++ {
		for i := 0; i < 50; i++ {
			seq++
			d.in <- icmpEcho(seq, 56)
		}
		time.Sleep(100 * time.Millisecond)
	}
	mark("bulk")
	for b := 0; b < 30; b++ {
		for i := 0; i < 64; i++ {
			seq++
			d.in <- icmpEcho(seq, 1372)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	mark("idle")
	time.Sleep(12 * time.Second)
	mark("end")
	fmt.Printf("RX %d packets %d bytes\n", d.rx.Load(), d.rxB.Load())
	s.Stop()
	d.Close()
	time.Sleep(300 * time.Millisecond)
}
