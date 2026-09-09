package obsidian

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTunnelConcurrentSendData(t *testing.T) {
	keyC := [KeySize]byte{1}
	ivC := [NonceSize]byte{2}
	keyS := [KeySize]byte{3}
	ivS := [NonceSize]byte{4}

	cliEnc, err := NewCipher(keyC, ivC)
	if err != nil {
		t.Fatal(err)
	}
	cliDec, err := NewCipher(keyS, ivS)
	if err != nil {
		t.Fatal(err)
	}
	srvEnc, err := NewCipher(keyS, ivS)
	if err != nil {
		t.Fatal(err)
	}
	srvDec, err := NewCipher(keyC, ivC)
	if err != nil {
		t.Fatal(err)
	}

	cliConn, srvConn := net.Pipe()
	cfg := DefaultTunnelConfig()
	cfg.Jitter = JitterOff
	cfg.NoiseMinInterval = time.Hour
	cfg.NoiseMaxInterval = time.Hour
	cfg.KeepaliveInterval = time.Hour
	cfg.KeepaliveJitter = 0

	client := NewTunnel(cliConn, NewStreamFramer(cliEnc, cliDec), cfg)
	server := NewTunnel(srvConn, NewStreamFramer(srvEnc, srvDec), cfg)
	defer client.Close()
	defer server.Close()

	const (
		workers          = 16
		packetsPerWorker = 32
		totalPackets     = workers * packetsPerWorker
	)

	received := make(chan uint32, totalPackets)
	recvDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for i := 0; i < totalPackets; i++ {
			data, err := server.RecvData(ctx)
			if err != nil {
				recvDone <- err
				return
			}
			if len(data) != 4 {
				recvDone <- errors.New("unexpected payload length")
				return
			}
			received <- binary.BigEndian.Uint32(data)
		}
		recvDone <- nil
	}()

	var wg sync.WaitGroup
	sendErr := make(chan error, totalPackets)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < packetsPerWorker; i++ {
				payload := make([]byte, 4)
				binary.BigEndian.PutUint32(payload, uint32(worker*packetsPerWorker+i))
				if err := client.SendData(payload); err != nil {
					sendErr <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(sendErr)
	for err := range sendErr {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-recvDone; err != nil {
		t.Fatal(err)
	}
	close(received)

	seen := make(map[uint32]struct{}, totalPackets)
	for id := range received {
		seen[id] = struct{}{}
	}
	for i := 0; i < totalPackets; i++ {
		if _, ok := seen[uint32(i)]; !ok {
			t.Fatalf("missing packet %d", i)
		}
	}
}
