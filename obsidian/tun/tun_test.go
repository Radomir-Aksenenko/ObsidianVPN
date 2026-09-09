package tun

import (
	"context"
	"testing"
	"time"
)

func TestPacketDevice(t *testing.T) {
	dev := NewPacketDevice("test-tun", 1420, 64)
	if dev.Name() != "test-tun" {
		t.Fatalf("expected name test-tun, got %s", dev.Name())
	}
	if dev.MTU() != 1420 {
		t.Fatalf("expected MTU 1420, got %d", dev.MTU())
	}

	// Test inject -> Read
	testPkt := []byte{0x45, 0x00, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04}
	if err := dev.InjectPacket(testPkt); err != nil {
		t.Fatalf("InjectPacket failed: %v", err)
	}

	readBuf := make([]byte, 1500)
	n, err := dev.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(testPkt) {
		t.Fatalf("expected read length %d, got %d", len(testPkt), n)
	}
	for i := range testPkt {
		if readBuf[i] != testPkt[i] {
			t.Fatalf("byte %d mismatch", i)
		}
	}

	// Test Write -> ReceivePacket
	writePkt := []byte{0x45, 0x00, 0x00, 0x30, 0x0a, 0x0b, 0x0c, 0x0d}
	wn, err := dev.Write(writePkt)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if wn != len(writePkt) {
		t.Fatalf("expected written %d, got %d", len(writePkt), wn)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	recvPkt, err := dev.ReceivePacket(ctx)
	if err != nil {
		t.Fatalf("ReceivePacket failed: %v", err)
	}
	if len(recvPkt) != len(writePkt) {
		t.Fatalf("expected len %d, got %d", len(writePkt), len(recvPkt))
	}

	// Test Close
	if err := dev.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if err := dev.InjectPacket(testPkt); err == nil {
		t.Fatal("expected error after close on InjectPacket")
	}
}

func TestStringHelpers(t *testing.T) {
	str := "  hello \t world \n foo   bar  "
	fields := splitFields(str)
	if len(fields) != 4 || fields[0] != "hello" || fields[1] != "world" || fields[2] != "foo" || fields[3] != "bar" {
		t.Fatalf("unexpected fields: %#v", fields)
	}

	multiline := "line1\r\nline2\nline3\n"
	lines := splitLines(multiline)
	if len(lines) != 3 || lines[0] != "line1" || lines[1] != "line2" || lines[2] != "line3" {
		t.Fatalf("unexpected lines: %#v", lines)
	}
}
