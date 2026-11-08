//go:build linux

package obsidian

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func withGSOWriter(t *testing.T, f func(conn *net.UDPConn, b, oob []byte, addr *net.UDPAddr) error) {
	t.Helper()
	orig := gsoWriteMsg
	gsoWriteMsg = f
	t.Cleanup(func() {
		gsoWriteMsg = orig
		gsoOff.Store(false)
	})
}

// On a kernel with UDP_SEGMENT the batch must leave in a few sendmsg calls, not one per packet,
// and the client must still see every datagram separately.
func TestSendBatchUsesGSO(t *testing.T) {
	sess, ch := newBatchPair(t, false)
	if !gsoAvailable(sess.outConn()) {
		t.Skip("kernel without UDP_SEGMENT")
	}
	calls := 0
	orig := gsoWriteMsg
	withGSOWriter(t, func(conn *net.UDPConn, b, oob []byte, addr *net.UDPAddr) error {
		calls++
		return orig(conn, b, oob, addr)
	})
	payloads := make([][]byte, 20)
	for i := range payloads {
		payloads[i] = make([]byte, 1300)
		payloads[i][0] = byte(i)
	}
	if sent, err := sess.SendBatch(payloads); err != nil || sent != len(payloads) {
		t.Fatalf("sent %d: %v", sent, err)
	}
	if calls != 1 {
		t.Fatalf("UDP_SEGMENT sends = %d, want 1 for 20 equal datagrams", calls)
	}
	recvAll(t, ch, payloads)
}

// A NIC without checksum offload answers EIO: the already sealed datagrams must go out one by
// one and GSO must stay off afterwards.
func TestSendBatchFallsBackOnEIO(t *testing.T) {
	sess, ch := newBatchPair(t, false)
	if !gsoAvailable(sess.outConn()) {
		t.Skip("kernel without UDP_SEGMENT")
	}
	calls := 0
	withGSOWriter(t, func(*net.UDPConn, []byte, []byte, *net.UDPAddr) error {
		calls++
		return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendmsg", unix.EIO)}
	})
	payloads := batchPayloads()
	if sent, err := sess.SendBatch(payloads); err != nil || sent != len(payloads) {
		t.Fatalf("sent %d: %v", sent, err)
	}
	recvAll(t, ch, payloads)
	if !gsoOff.Load() {
		t.Fatal("GSO still on after EIO")
	}
	if calls != 1 {
		t.Fatalf("GSO attempts after EIO = %d, want 1", calls)
	}
}
