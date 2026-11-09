//go:build linux

package obsidian

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

type syscallRawConn interface {
	Control(func(fd uintptr)) error
}

func getInt(t *testing.T, rc syscallRawConn, level, opt int) int {
	t.Helper()
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) { v, gerr = unix.GetsockoptInt(int(fd), level, opt) }); err != nil {
		t.Fatal(err)
	}
	if gerr != nil {
		t.Fatal(gerr)
	}
	return v
}

// The tunnel socket must keep the kernel's autotuned buffers and get the unsent-queue cap.
func TestSetOptimalTCPConnKeepsAutotuning(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			_, _ = c.Read(buf)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	rc, _ := tc.SyscallConn()
	before := getInt(t, rc, unix.SOL_SOCKET, unix.SO_RCVBUF)

	setOptimalTCPConn(tc)

	if got := getInt(t, rc, unix.SOL_SOCKET, unix.SO_RCVBUF); got != before {
		t.Fatalf("SO_RCVBUF changed from %d to %d: that disables autotuning", before, got)
	}
	if got := getInt(t, rc, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT); got != tcpNotSentLowat {
		t.Fatalf("TCP_NOTSENT_LOWAT = %d, want %d", got, tcpNotSentLowat)
	}
	if got := getInt(t, rc, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT); got != int(tcpUserTimeout.Milliseconds()) {
		t.Fatalf("TCP_USER_TIMEOUT = %d, want %d", got, tcpUserTimeout.Milliseconds())
	}
	if got := getInt(t, rc, unix.IPPROTO_TCP, unix.TCP_NODELAY); got == 0 {
		t.Fatal("TCP_NODELAY not set")
	}
}

func TestSetUDPSocketBuffersReportsKernelSize(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rcv, snd, err := SetUDPSocketBuffers(c, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if rcv <= 0 || snd <= 0 {
		t.Fatalf("kernel sizes not reported: rcv=%d snd=%d", rcv, snd)
	}
	t.Logf("requested 1 MiB, kernel reports rcv=%d snd=%d", rcv, snd)
}

// The effective congestion control is read back, so a missing module shows up in the log.
func TestSetTCPCongestionReportsEffective(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := setTCPCongestion(c.(*net.TCPConn), "no-such-cc"); got == "" || got == "no-such-cc" {
		t.Fatalf("effective congestion control = %q", got)
	}
	t.Logf("bbr -> %s", setTCPCongestion(c.(*net.TCPConn), "bbr"))
}
