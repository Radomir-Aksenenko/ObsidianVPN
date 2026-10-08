package obsidian

import (
	"io"
	"net"
	"testing"
	"time"
)

// Jitter must not turn a bulk transfer into a per-packet sleep loop. With the
// old per-packet implementation, 300 back-to-back packets under JitterHeavy
// (0-50 ms each, ~25 ms average) take ~7.5 s; a burst-level jitter takes at
// most one sleep for the whole burst.
func TestTunnelJitterDoesNotThrottleBulkBursts(t *testing.T) {
	keyC := [KeySize]byte{7}
	ivC := [NonceSize]byte{8}
	keyS := [KeySize]byte{9}
	ivS := [NonceSize]byte{10}

	cliEnc, _ := NewCipher(keyC, ivC)
	cliDec, _ := NewCipher(keyS, ivS)
	srvEnc, _ := NewCipher(keyS, ivS)
	srvDec, _ := NewCipher(keyC, ivC)

	cliConn, srvConn := net.Pipe()
	cfg := DefaultTunnelConfig()
	cfg.Jitter = JitterHeavy
	cfg.NoiseMinInterval = time.Hour
	cfg.NoiseMaxInterval = time.Hour
	cfg.KeepaliveInterval = time.Hour
	cfg.KeepaliveJitter = 0

	client := NewTunnel(cliConn, NewStreamFramer(cliEnc, cliDec), cfg)
	server := NewTunnel(srvConn, NewStreamFramer(srvEnc, srvDec), cfg)
	defer client.Close()
	defer server.Close()

	// Drain the server side so net.Pipe writes never block.
	go func() { _, _ = io.Copy(io.Discard, srvConn) }()

	const packets = 300
	payload := make([]byte, 1200)
	start := time.Now()
	for i := 0; i < packets; i++ {
		if err := client.SendData(payload); err != nil {
			t.Fatalf("SendData %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("bulk burst of %d packets took %v under JitterHeavy; jitter is throttling the data path per packet", packets, elapsed)
	}
}
