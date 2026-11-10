package client

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

type chanTun struct{ in chan []byte }

func (c *chanTun) Read(b []byte) (int, error) {
	p, ok := <-c.in
	if !ok {
		return 0, io.EOF
	}
	return copy(b, p), nil
}

func TestTunBatchReaderLonePacketDoesNotWait(t *testing.T) {
	tun := &chanTun{in: make(chan []byte)}
	r := NewTunBatchReader(tun)
	defer r.Close()
	go func() { tun.in <- []byte{0x45, 1, 2} }()
	start := time.Now()
	batch, err := r.NextBatch(nil, nil)
	if err != nil || len(batch) != 1 || !bytes.Equal(*batch[0], []byte{0x45, 1, 2}) {
		t.Fatalf("got %v %v", batch, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a lone packet waited for a batch to fill")
	}
	r.Release(batch)
}

func TestTunBatchReaderTakesQueuedPacketsInOrder(t *testing.T) {
	tun := &chanTun{in: make(chan []byte, 100)}
	for i := 0; i < 40; i++ {
		tun.in <- []byte{byte(i)}
	}
	r := NewTunBatchReader(tun)
	defer r.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(r.pkts) < 40 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	batch, err := r.NextBatch(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != UplinkBatchPackets {
		t.Fatalf("batch has %d packets, want %d", len(batch), UplinkBatchPackets)
	}
	for i, bp := range batch {
		if (*bp)[0] != byte(i) {
			t.Fatalf("packet %d out of order", i)
		}
	}
	r.Release(batch)
	batch, _ = r.NextBatch(nil, nil)
	if len(batch) != 8 || (*batch[0])[0] != 32 {
		t.Fatalf("second batch wrong: %d packets", len(batch))
	}
}

func TestTunBatchReaderReportsReadErrorAndStop(t *testing.T) {
	tun := &chanTun{in: make(chan []byte)}
	close(tun.in)
	r := NewTunBatchReader(tun)
	defer r.Close()
	if _, err := r.NextBatch(nil, nil); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
	stop := make(chan struct{})
	close(stop)
	r2 := NewTunBatchReader(&chanTun{in: make(chan []byte)})
	defer r2.Close()
	if b, err := r2.NextBatch(nil, stop); b != nil || err != nil {
		t.Fatal("stop must return nil, nil")
	}
}
