package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDNSProxyConcurrentQueries(t *testing.T) {
	// Start a mock upstream DNS server that echoes requests back with high bit flipped in flags
	upstreamConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamConn.Close()

	upstreamAddr := upstreamConn.LocalAddr().String()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := upstreamConn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			if len(resp) >= 4 {
				// Mark as standard response
				resp[2] |= 0x80
			}
			_, _ = upstreamConn.WriteTo(resp, addr)
		}
	}()

	// Start DNS proxy listening on another local port
	proxyConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	defer proxyConn.Close()

	go serveDNSUDP(proxyConn, upstreamAddr)

	proxyAddr := proxyConn.LocalAddr().String()

	// Send concurrent queries with unique transaction IDs and verify responses
	const numQueries = 50
	var wg sync.WaitGroup
	errCh := make(chan error, numQueries)

	for i := 0; i < numQueries; i++ {
		wg.Add(1)
		go func(id uint16) {
			defer wg.Done()

			clientConn, err := net.Dial("udp4", proxyAddr)
			if err != nil {
				errCh <- fmt.Errorf("dial proxy: %w", err)
				return
			}
			defer clientConn.Close()

			_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))

			// Construct minimal query with transaction ID
			query := make([]byte, 12+len("example.com")+4)
			binary.BigEndian.PutUint16(query[0:2], id)
			// Put some dummy data
			for j := 12; j < len(query); j++ {
				query[j] = byte(j)
			}

			if _, err := clientConn.Write(query); err != nil {
				errCh <- fmt.Errorf("write query %d: %w", id, err)
				return
			}

			resp := make([]byte, 4096)
			n, err := clientConn.Read(resp)
			if err != nil {
				errCh <- fmt.Errorf("read response %d: %w", id, err)
				return
			}

			if n < 12 {
				errCh <- fmt.Errorf("response %d too short: %d", id, n)
				return
			}

			gotID := binary.BigEndian.Uint16(resp[0:2])
			if gotID != id {
				errCh <- fmt.Errorf("transaction ID mismatch: got %d, want %d", gotID, id)
				return
			}

			if !bytes.Equal(query[12:], resp[12:n]) {
				errCh <- fmt.Errorf("payload corrupted for query %d", id)
				return
			}
		}(uint16(i + 1000))
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent DNS failure: %v", err)
	}
}
