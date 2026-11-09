package obsidian

import (
	"bytes"
	"crypto/mlkem"
	"io"
	"net"
	"testing"
)

type recordBufferConn struct {
	net.Conn
	buf bytes.Buffer
}

func (c *recordBufferConn) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *recordBufferConn) Read(p []byte) (int, error)  { return c.buf.Read(p) }

// No VPN key is used: ML-KEM's encoded polynomial coefficients must be canonical
// integers below 3329. Random TLS ciphertext almost never passes all 768 checks.
func containsMLKEMKey(wire []byte) bool {
	for i := 0; i+MLKEM768EncapsulationKeySize <= len(wire); i++ {
		if _, err := mlkem.NewEncapsulationKey768(wire[i : i+MLKEM768EncapsulationKeySize]); err == nil {
			return true
		}
	}
	return false
}

func TestRealityRecordsHideMLKEMHandshake(t *testing.T) {
	kp, _ := GenerateKeypair()
	hs, err := NewClientHandshake(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := hs.BuildHello()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := BuildHelloFrame(kp.Public, hello)
	if err != nil {
		t.Fatal(err)
	}

	old := new(recordBufferConn)
	if _, err := newTLSRecordConn(old).Write(frame); err != nil {
		t.Fatal(err)
	}
	if !containsMLKEMKey(old.buf.Bytes()) {
		t.Fatal("detector must reproduce the unencrypted v4 handshake leak")
	}
	key, sid := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	wire := new(recordBufferConn)
	tx, err := newRealityRecordConn(wire, key, sid, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Write(frame); err != nil {
		t.Fatal(err)
	}
	if containsMLKEMKey(wire.buf.Bytes()) {
		t.Fatal("canonical ML-KEM public key remains visible on the wire")
	}
	recordTypes(t, "protected handshake", wire.buf.Bytes())
	rx, err := newRealityRecordConn(wire, key, sid, false)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(rx, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, got) {
		t.Fatal("handshake changed after record decryption")
	}
}

func TestRealityProtectedRecordStream(t *testing.T) {
	for _, client := range []bool{false, true} {
		key, sid := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
		wire := new(recordBufferConn)
		tx, err := newRealityRecordConn(wire, key, sid, client)
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Repeat([]byte("hello"), 17000)
		if _, err := tx.Write(want); err != nil {
			t.Fatal(err)
		}
		rx, err := newRealityRecordConn(wire, key, sid, !client)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		// Exercise partial application reads across several TLS records.
		for i := 0; i < len(got); {
			n, err := rx.Read(got[i:min(i+71, len(got))])
			if err != nil {
				t.Fatal(err)
			}
			i += n
		}
		if !bytes.Equal(got, want) {
			t.Fatal("record stream lost data")
		}
	}
}

func TestRealityRecordRejectsTamperingReplayAndReflection(t *testing.T) {
	key, sid := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	for _, attack := range []string{"tamper", "replay", "reflection", "different-session"} {
		t.Run(attack, func(t *testing.T) {
			wire := new(recordBufferConn)
			tx, _ := newRealityRecordConn(wire, key, sid, true)
			_, _ = tx.Write([]byte("one"))
			first := bytes.Clone(wire.buf.Bytes())
			_, _ = tx.Write([]byte("two"))
			raw := bytes.Clone(wire.buf.Bytes())
			role, salt := false, sid
			switch attack {
			case "tamper":
				raw[len(raw)-1] ^= 1
			case "replay":
				raw = append(first, first...)
			case "reflection":
				role = true
			case "different-session":
				salt = bytes.Repeat([]byte{3}, 32)
			}
			in := new(recordBufferConn)
			_, _ = in.Write(raw)
			rx, _ := newRealityRecordConn(in, key, salt, role)
			got := make([]byte, 3)
			if attack == "tamper" || attack == "replay" {
				if _, err := io.ReadFull(rx, got); err != nil || string(got) != "one" {
					t.Fatalf("first record: %q, %v", got, err)
				}
			}
			if n, err := rx.Read(got); err == nil || n != 0 {
				t.Fatalf("accepted %s: %q, %v", attack, got[:n], err)
			}
		})
	}
}
