// Command rtcprobe imitates a Discord voice connection over UDP: IP discovery, then a 50 pps Opus-sized
// stream with echo, plus a sweep of datagram sizes in both directions. Prints a summary.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync/atomic"
	"time"
)

func main() {
	target := flag.String("t", "198.51.100.2:50001", "voice server")
	secs := flag.Int("d", 5, "stream seconds")
	pps := flag.Int("pps", 50, "packets per second")
	size := flag.Int("s", 160, "stream packet size")
	skip := flag.Bool("skip", false, "skip discovery and sweep")
	flag.Parse()
	c, err := net.Dial("udp", *target)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(2)
	}
	fail := false
	if !*skip {
		// 1. IP discovery, retried like the Discord client (it gives up after a few seconds).
		req := make([]byte, 74)
		binary.BigEndian.PutUint16(req[0:2], 1)
		binary.BigEndian.PutUint16(req[2:4], 70)
		binary.BigEndian.PutUint32(req[4:8], 12345)
		buf := make([]byte, 65535)
		start := time.Now()
		got := false
		for i := 0; i < 10 && !got; i++ {
			c.Write(req)
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := c.Read(buf)
			if err == nil && n == 74 && binary.BigEndian.Uint16(buf[0:2]) == 2 {
				got = true
				fmt.Printf("ipdiscovery ok after %v\n", time.Since(start).Round(time.Millisecond))
			}
		}
		if !got {
			fmt.Println("ipdiscovery FAILED")
			fail = true
		}
		// 2. Size sweep: uplink echo and downlink big replies.
		for _, sz := range []int{100, 600, 1000, 1200, 1300, 1372, 1400, 1450, 1472, 2000, 4000} {
			p := make([]byte, sz)
			copy(p, "ECHO")
			okUp := false
			for try := 0; try < 3 && !okUp; try++ {
				c.Write(p)
				c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
				n, err := c.Read(buf)
				okUp = err == nil && n == sz
			}
			okDown := false
			for try := 0; try < 3 && !okDown; try++ {
				c.Write([]byte(fmt.Sprintf("BIG:%d", sz)))
				c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
				n, err := c.Read(buf)
				okDown = err == nil && n == sz
			}
			fmt.Printf("size %5d echo=%v downlink=%v\n", sz, okUp, okDown)
			if sz <= 1400 && (!okUp || !okDown) {
				fail = true
			}
		}
	}
	// 3. Voice stream: pps packets of size bytes, measure loss, RTT and jitter.
	total := *secs * *pps
	sent := make([]time.Time, total)
	answered := make([]bool, total)
	var rtts []time.Duration
	recvd := 0
	done := make(chan struct{})
	var finished atomic.Bool
	go func() {
		b := make([]byte, 65535)
		for {
			c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := c.Read(b)
			if err != nil {
				if finished.Load() {
					close(done)
					return
				}
				continue
			}
			if n == *size && string(b[:4]) == "RTPx" {
				seq := int(binary.BigEndian.Uint32(b[4:8]))
				if seq < total && !answered[seq] {
					answered[seq] = true
					rtts = append(rtts, time.Since(sent[seq]))
					recvd++
				}
			}
		}
	}()
	tick := time.NewTicker(time.Second / time.Duration(*pps))
	for i := 0; i < total; i++ {
		<-tick.C
		p := make([]byte, *size)
		copy(p, "RTPx")
		binary.BigEndian.PutUint32(p[4:8], uint32(i))
		sent[i] = time.Now()
		c.Write(p)
	}
	time.Sleep(1500 * time.Millisecond)
	finished.Store(true)
	<-done
	// Gaps: runs of consecutive sequence numbers without an answer.
	worst, gaps := 0, 0
	run := 0
	for i := 0; i < total; i++ {
		if answered[i] {
			if run > 0 {
				gaps++
			}
			run = 0
			continue
		}
		run++
		if run > worst {
			worst = run
		}
	}
	if run > 0 {
		gaps++
	}
	fmt.Printf("gaps %d, longest %v\n", gaps, time.Duration(worst)*time.Second/time.Duration(*pps))
	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	pct := func(q float64) time.Duration {
		if len(rtts) == 0 {
			return 0
		}
		return rtts[int(float64(len(rtts)-1)*q)].Round(100 * time.Microsecond)
	}
	loss := 100 * float64(total-recvd) / float64(total)
	fmt.Printf("stream %d pkts x %dB: received %d loss %.1f%% rtt p50=%v p95=%v p99=%v max=%v\n", total, *size, recvd, loss, pct(.5), pct(.95), pct(.99), pct(1))
	if loss > 2 {
		fail = true
	}
	if fail {
		fmt.Println("RESULT FAIL")
		os.Exit(1)
	}
	fmt.Println("RESULT OK")
}
