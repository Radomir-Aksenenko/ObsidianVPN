package obsidian

import (
	"bytes"
	"net"
	"testing"
	"time"
)

type flightStep struct {
	pause time.Duration // before this record
	rec   []byte
	stall time.Duration // inside this record, after its first half
}

func encRec(n int) []byte {
	return append(appendRecordHeader(nil, recordTypeAppData, n), make([]byte, n)...)
}

func ccsRec() []byte { return append(appendRecordHeader(nil, recordTypeCCS, 1), 1) }

// fullFlight is SH, CCS, EE, Certificate, CertificateVerify, Finished (53 bytes for AES-128).
func fullFlight(eeSize int, certPause time.Duration) []flightStep {
	return []flightStep{
		{rec: buildTLSServerHelloRecord(make([]byte, 32))},
		{rec: ccsRec()},
		{rec: encRec(eeSize)},
		{pause: certPause, rec: encRec(2900)},
		{rec: encRec(281)},
		{rec: encRec(53)},
	}
}

// playFlight writes the flight and reports the moment it starts writing the last record, so a
// reader that returns after that record always finds the report already there.
func playFlight(w net.Conn, steps []flightStep, finished chan<- time.Time) {
	for i, s := range steps {
		time.Sleep(s.pause)
		if i == len(steps)-1 {
			finished <- time.Now()
		}
		if s.stall > 0 {
			half := len(s.rec) / 2
			_, _ = w.Write(s.rec[:half])
			time.Sleep(s.stall)
			_, _ = w.Write(s.rec[half:])
		} else {
			_, _ = w.Write(s.rec)
		}
	}
}

func runClientFlight(t *testing.T, steps []flightStep) (time.Duration, error) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan time.Time, 1)
	go playFlight(server, steps, done)
	size, err := awaitServerFlight(client)
	returned := time.Now()
	if err != nil {
		return 0, err
	}
	if size != 53 {
		t.Fatalf("Finished size %d, want 53", size)
	}
	select {
	case last := <-done:
		return returned.Sub(last), nil
	default:
		t.Fatal("client answered before the target finished its flight")
	}
	return 0, nil
}

// The client must answer right after the server's Finished, even when the target pauses before
// its certificate for longer than the idle gap, and must not be fooled by an EE of Finished size.
func TestAwaitServerFlightEndsOnFinished(t *testing.T) {
	for name, steps := range map[string][]flightStep{
		"plain":               fullFlight(36, 0),
		"pause before cert":   fullFlight(36, 3*flightIdleGap),
		"EE of Finished size": fullFlight(53, 0),
		"stall inside cert": func() []flightStep {
			s := fullFlight(36, 0)
			s[3].stall = 3 * flightIdleGap
			return s
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			lag, err := runClientFlight(t, steps)
			if err != nil {
				t.Fatal(err)
			}
			if lag > flightIdleGap/2 {
				t.Fatalf("answered %v after the server Finished, want well under the idle gap", lag)
			}
		})
	}
}

// A target that coalesces the encrypted flight into one record has no separate Finished; the
// idle gap still ends the flight.
func TestAwaitServerFlightCoalescedFallsBackToIdleGap(t *testing.T) {
	steps := []flightStep{
		{rec: buildTLSServerHelloRecord(make([]byte, 32))},
		{rec: ccsRec()},
		{rec: encRec(3300)},
	}
	lag, err := runClientFlight(t, steps)
	if err != nil {
		t.Fatal(err)
	}
	if lag < flightIdleGap/2 {
		t.Fatalf("coalesced flight ended after %v, expected to wait for the idle gap", lag)
	}
}

// The server relay must stream the whole flight, pauses and stalls included, and stop right
// after the target's Finished instead of waiting for the idle gap.
func TestStreamFlightEndsOnFinished(t *testing.T) {
	steps := fullFlight(36, 3*flightIdleGap)
	steps[3].stall = 2 * flightIdleGap
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan time.Time, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf) // the ClientHello
		playFlight(c, steps, done)
		time.Sleep(2 * time.Second) // stay open like a real server waiting for the client
	}()
	var out bytes.Buffer
	sent, sawEnc, err := streamFlight(&out, ln.Addr().String(), []byte("hello"), 2*time.Second)
	returned := time.Now()
	if err != nil || !sawEnc {
		t.Fatalf("relay: sent=%d enc=%v err=%v", sent, sawEnc, err)
	}
	var want int
	for _, s := range steps {
		want += len(s.rec)
	}
	if sent != want || out.Len() != want {
		t.Fatalf("relayed %d bytes (buffer %d), want %d", sent, out.Len(), want)
	}
	last := <-done
	if lag := returned.Sub(last); lag > flightIdleGap/2 {
		t.Fatalf("relay ended %v after the target Finished", lag)
	}
}
