package obsidian

import (
	"bytes"
	"io"
	"testing"
)

// The record counter boundary used to end the session. Both peers now step to the next key there,
// so a stream crossing it several times stays readable, and the key really changes.
func TestRealityRecordKeyStepsAtLimit(t *testing.T) {
	old := maxRealityRecords
	maxRealityRecords = 3
	defer func() { maxRealityRecords = old }()

	key, sid := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	wire := new(recordBufferConn)
	tx, err := newRealityRecordConn(wire, key, sid, true)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := tx.encKey
	rx, err := newRealityRecordConn(wire, key, sid, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		msg := bytes.Repeat([]byte{byte(i)}, 100+i)
		if _, err := tx.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(rx, got); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("record %d changed", i)
		}
	}
	if tx.encKey == firstKey {
		t.Fatal("write key did not change after crossing the record limit")
	}
	if tx.encKey != rx.decKey {
		t.Fatal("peers disagree on the current key")
	}
}

// A record sealed after the step must not open under the old key: a peer that does not step
// (an older core) fails at the boundary instead of silently accepting a reused nonce.
func TestRealityRecordOldKeyRejectsSteppedRecord(t *testing.T) {
	old := maxRealityRecords
	maxRealityRecords = 2
	defer func() { maxRealityRecords = old }()

	key, sid := bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{4}, 32)
	wire := new(recordBufferConn)
	tx, _ := newRealityRecordConn(wire, key, sid, true)
	rx, _ := newRealityRecordConn(wire, key, sid, false)
	buf := make([]byte, 8)
	for i := 0; i < 2; i++ {
		if _, err := tx.Write([]byte("abcdefgh")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(rx, buf); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Write([]byte("abcdefgh")); err != nil {
		t.Fatal(err)
	}
	// Simulate the old reader: keep the old key and keep counting.
	maxRealityRecords = 1 << 24
	if _, err := io.ReadFull(rx, buf); err == nil {
		t.Fatal("record under the stepped key opened with the old key")
	}
}
