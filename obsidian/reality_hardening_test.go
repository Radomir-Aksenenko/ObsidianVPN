package obsidian

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestRealityStrictModeNeverDowngrades(t *testing.T) {
	var selector RealityAuthSelector
	for i := 0; i < 20; i++ {
		if mode := selector.Mode(); mode != RealityAuthRecords {
			t.Fatalf("network failure %d downgraded the wire format to %v", i, mode)
		}
		selector.Reject()
		if i%2 == 0 {
			selector.Confirm()
		}
	}
}

func TestRealityFinishedMatchesNegotiatedCipher(t *testing.T) {
	for _, tc := range []struct {
		name  string
		suite uint16
		want  int
	}{
		{"aes128", tls.TLS_AES_128_GCM_SHA256, 53},
		{"aes256", tls.TLS_AES_256_GCM_SHA384, 69},
		{"chacha", tls.TLS_CHACHA20_POLY1305_SHA256, 53},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := buildTLSServerHelloRecord(make([]byte, 32))
			binary.BigEndian.PutUint16(rec[76:78], tc.suite)
			n, err := serverFinishedRecordSize(rec)
			if err != nil || n != tc.want {
				t.Fatalf("Finished size = %d, %v; want %d", n, err, tc.want)
			}
			finish := clientFinishRecords(n)
			// Six bytes of CCS, then five bytes of the encrypted record header.
			if got := int(binary.BigEndian.Uint16(finish[9:11])); got != tc.want || len(finish) != 11+tc.want {
				t.Fatalf("wrong Finished on wire: %x", finish)
			}
		})
	}
}

func TestRealityRejectsHelloRetryRequest(t *testing.T) {
	rec := buildTLSServerHelloRecord(make([]byte, 32))
	hrr := []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	copy(rec[11:43], hrr)
	if _, err := serverFinishedRecordSize(rec); err == nil {
		t.Fatal("would send Finished instead of a second ClientHello")
	}
}

func TestRealityMissingTargetDoesNotInventFlight(t *testing.T) {
	var out bytes.Buffer
	if err := relayFirstFlight(&out, "", nil, nil, time.Second); err == nil || out.Len() != 0 {
		t.Fatalf("invented flight: %d bytes, err=%v", out.Len(), err)
	}
}

type failEncryptedRecordWriter struct{ err error }

func (w failEncryptedRecordWriter) Write(p []byte) (int, error) {
	if len(p) > 0 && p[0] == recordTypeAppData {
		return 0, w.err
	}
	return len(p), nil
}

func TestRealityFlightPropagatesEncryptedWriteFailure(t *testing.T) {
	sid, _ := GenerateRecordSessionID([]byte("key"), "example.com")
	ch, err := BuildTLSClientHelloRecord("example.com", sid[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("client connection failed")
	err = relayFirstFlight(failEncryptedRecordWriter{want}, startTLSTarget(t), ch, sid[:], time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("lost client write error: %v", err)
	}
}

func TestRealityServerRejectsLegacyByDefault(t *testing.T) {
	key := []byte("secret-auth-key-at-least-16")
	for _, generate := range []func([]byte, string) ([32]byte, error){GenerateSessionID, GenerateMaskedSessionID} {
		client, server := net.Pipe()
		sid, _ := generate(key, "example.com")
		hello, err := BuildTLSClientHelloRecord("example.com", sid[:], nil)
		if err != nil {
			t.Fatal(err)
		}
		d := NewRealityDemuxer(RealityDemuxConfig{AuthKey: key}, nil)
		result := make(chan bool, 1)
		go func() {
			conn, ok := d.processIncoming(server)
			if conn != nil {
				conn.Close()
			}
			result <- ok
		}()
		_ = client.SetDeadline(time.Now().Add(time.Second))
		_, _ = client.Write(hello)
		select {
		case ok := <-result:
			if ok {
				t.Fatal("new server accepted the raw legacy wire format")
			}
		case <-time.After(time.Second):
			t.Fatal("legacy classification stalled")
		}
		client.Close()
		server.Close()
	}
}

func TestRealityClientWaitsForRestOfFlight(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	lastRecord := make(chan struct{})
	go func() {
		_, _ = server.Write(buildTLSServerHelloRecord(make([]byte, 32)))
		rec := append(appendRecordHeader(nil, recordTypeAppData, 53), make([]byte, 53)...)
		_, _ = server.Write(rec)
		time.Sleep(30 * time.Millisecond)
		_, _ = server.Write(rec)
		close(lastRecord)
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := awaitServerFlight(client); err != nil {
		t.Fatal(err)
	}
	select {
	case <-lastRecord:
	default:
		t.Fatal("would send client Finished before the last server flight record")
	}
}

func TestRealityPartialRecordIsNotIdleGap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = server.Write([]byte{0x17, 0x03, 0x03}) }()
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := readTLSRecord(client); !errors.Is(err, errPartialTLSRecord) {
		t.Fatalf("partial header mistaken for a complete flight: %v", err)
	}
}
