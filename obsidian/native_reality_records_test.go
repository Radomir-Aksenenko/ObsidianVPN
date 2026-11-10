package obsidian

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// recordingProxy forwards TCP to target and keeps a copy of the client to server bytes.
type recordingProxy struct {
	ln net.Listener
	mu sync.Mutex
	up bytes.Buffer
	wg sync.WaitGroup
}

func newRecordingProxy(t *testing.T, target string) *recordingProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &recordingProxy{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			p.wg.Add(2)
			go func() { defer p.wg.Done(); _, _ = io.Copy(c, s); c.Close() }()
			go func() {
				defer p.wg.Done()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						p.mu.Lock()
						p.up.Write(buf[:n])
						p.mu.Unlock()
						_, _ = s.Write(buf[:n])
					}
					if err != nil {
						s.Close()
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *recordingProxy) upstream() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.up.Bytes()...)
}

// A large write on a native REALITY client must leave as one record sized by the write, the way
// Chrome sends it, not as a run of 1203-byte records from Go TLS dynamic record sizing.
func TestNativeRealityRecordsFollowWrites(t *testing.T) {
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	cover.StartTLS()
	defer cover.Close()
	transportKey, _ := GenerateKeypair()
	shortID := "1234567890abcdef"
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := NewNativeRealityListener(ctx, raw, NativeRealityServerConfig{
		Target: cover.Listener.Addr().String(), ServerNames: []string{"example.com"},
		PrivateKey: hex.EncodeToString(transportKey.Private[:]), ShortIDs: []string{shortID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	const size = 5000
	got := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadFull(conn, make([]byte, size))
		got <- err
	}()
	proxy := newRecordingProxy(t, ln.Addr().String())
	_, port, _ := net.SplitHostPort(proxy.ln.Addr().String())
	conn, err := DialNativeReality(context.Background(), ClientTransportConfig{ServerHost: "127.0.0.1", ServerPort: port, SNI: "example.com"}, hex.EncodeToString(transportKey.Public[:]), shortID, "chrome")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	stream := proxy.upstream()
	var sizes []int
	for len(stream) >= 5 {
		n := int(stream[3])<<8 | int(stream[4])
		if len(stream) < 5+n {
			break
		}
		if stream[0] == recordTypeAppData {
			sizes = append(sizes, n)
		}
		stream = stream[5+n:]
	}
	for _, n := range sizes {
		if n >= size {
			return
		}
	}
	t.Fatalf("no application record carried the %d byte write whole; record sizes %v", size, sizes)
}
