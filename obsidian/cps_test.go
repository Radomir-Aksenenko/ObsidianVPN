package obsidian

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ── CPS Parser ────────────────────────────────────────────────────────────────

func TestCPSParseBytes(t *testing.T) {
	sig, err := ParseCPS(`<b 0xdeadbeef>`)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := sig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("got %x, want deadbeef", pkt)
	}
}

func TestCPSParseTimestamp(t *testing.T) {
	sig, err := ParseCPS(`<t>`)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := sig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 4 {
		t.Fatalf("timestamp should be 4 bytes, got %d", len(pkt))
	}
	ts := binary.LittleEndian.Uint32(pkt)
	if ts == 0 {
		t.Fatal("timestamp should not be zero")
	}
}

func TestCPSParseRandom(t *testing.T) {
	sig, err := ParseCPS(`<r 64>`)
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := sig.Generate()
	p2, _ := sig.Generate()
	if len(p1) != 64 || len(p2) != 64 {
		t.Fatal("wrong length")
	}
	// Два разных вызова должны давать разный результат (с подавляющей вероятностью)
	if bytes.Equal(p1, p2) {
		t.Fatal("random bytes should differ between calls")
	}
}

func TestCPSParseAlnum(t *testing.T) {
	sig, err := ParseCPS(`<rc 16>`)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := sig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(pkt))
	}
	for _, b := range pkt {
		if !isAlnum(b) {
			t.Fatalf("non-alnum byte: 0x%02x (%c)", b, b)
		}
	}
}

func TestCPSParseDigit(t *testing.T) {
	sig, err := ParseCPS(`<rd 8>`)
	if err != nil {
		t.Fatal(err)
	}
	pkt, _ := sig.Generate()
	for _, b := range pkt {
		if b < '0' || b > '9' {
			t.Fatalf("non-digit byte: %c", b)
		}
	}
}

func TestCPSComplex(t *testing.T) {
	// QUIC-подобная сигнатура из статьи AWG 2.0
	sig, err := ParseCPS(`<b 0xc700000001><rc 8><t><r 100>`)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := sig.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Минимальный размер: 5 + 8 + 4 + 100 = 117
	if len(pkt) < 117 {
		t.Fatalf("packet too short: %d", len(pkt))
	}
	// Первые байты должны быть фиксированными
	if !bytes.Equal(pkt[:5], []byte{0xc7, 0x00, 0x00, 0x00, 0x01}) {
		t.Fatalf("QUIC header mismatch: %x", pkt[:5])
	}
	// Байты 5–12: alnum
	for _, b := range pkt[5:13] {
		if !isAlnum(b) {
			t.Fatalf("expected alnum at connection id: %c", b)
		}
	}
}

func TestCPSPresets(t *testing.T) {
	presets := []string{PresetQUIC, PresetDNS, PresetSIP, PresetSTUN}
	names := []string{"QUIC", "DNS", "SIP", "STUN"}
	for i, p := range presets {
		sig, err := ParseCPS(p)
		if err != nil {
			t.Fatalf("preset %s parse error: %v", names[i], err)
		}
		pkt, err := sig.Generate()
		if err != nil {
			t.Fatalf("preset %s generate error: %v", names[i], err)
		}
		if len(pkt) == 0 {
			t.Fatalf("preset %s produced empty packet", names[i])
		}
	}
}

func TestCPSInvalidTag(t *testing.T) {
	_, err := ParseCPS(`<unknown 5>`)
	if err == nil {
		t.Fatal("should reject unknown tag")
	}
}

func TestCPSUnclosedTag(t *testing.T) {
	_, err := ParseCPS(`<r 10`)
	if err == nil {
		t.Fatal("should reject unclosed tag")
	}
}

func TestCPSZeroLength(t *testing.T) {
	_, err := ParseCPS(`<r 0>`)
	if err == nil {
		t.Fatal("should reject zero length")
	}
}

func TestCPSSignatureTrain(t *testing.T) {
	quic, _ := ParseCPS(PresetQUIC)
	dns, _ := ParseCPS(PresetDNS)
	data, err := BuildSignatureTrain([]*CPSSignature{quic, dns})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty signature train")
	}
	// Разбираем фреймы
	buf := data
	count := 0
	for len(buf) >= 4 {
		flen := int(binary.BigEndian.Uint32(buf[:4]))
		if len(buf) < 4+flen {
			t.Fatalf("truncated frame at %d", count)
		}
		buf = buf[4+flen:]
		count++
	}
	if count != 2 {
		t.Fatalf("expected 2 signature frames, got %d", count)
	}
}

func TestCPSNilSignatures(t *testing.T) {
	data, err := BuildSignatureTrain(nil)
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Fatal("nil signatures should return nil")
	}
}

func isAlnum(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// ── Range Headers ─────────────────────────────────────────────────────────────

func TestHeaderRangePick(t *testing.T) {
	h := HeaderRange{Min: 100, Max: 200}
	seen := make(map[uint32]bool)
	for i := 0; i < 1000; i++ {
		v := h.Pick()
		if v < 100 || v > 200 {
			t.Fatalf("value %d out of range [100,200]", v)
		}
		seen[v] = true
	}
	// После 1000 итераций должны видеть несколько разных значений
	if len(seen) < 5 {
		t.Fatal("header range should produce varied values")
	}
}

func TestHeaderRangeContains(t *testing.T) {
	h := HeaderRange{Min: 0x10000000, Max: 0x1FFFFFFF}
	if !h.Contains(0x10000000) || !h.Contains(0x15000000) || !h.Contains(0x1FFFFFFF) {
		t.Fatal("contains check failed")
	}
	if h.Contains(0x0FFFFFFF) || h.Contains(0x20000000) {
		t.Fatal("contains should be false outside range")
	}
}

func TestHeaderConfigNoOverlap(t *testing.T) {
	hc := DefaultHeaderConfig()
	if err := hc.Validate(); err != nil {
		t.Fatalf("default header config has overlapping ranges: %v", err)
	}
}

func TestHeaderConfigOverlapDetected(t *testing.T) {
	hc := DefaultHeaderConfig()
	hc.Keepalive = hc.Data // намеренно пересекаем
	if err := hc.Validate(); err == nil {
		t.Fatal("should detect overlapping ranges")
	}
}

func TestRangeHeadersInProtocol(t *testing.T) {
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	for i := range key {
		key[i] = byte(i)
	}
	enc, _ := NewCipher(key, iv)
	dec, _ := NewCipher(key, iv)

	hc := DefaultHeaderConfig()
	// Кодируем DATA пакет
	raw, err := encodePacket(enc, &hc, PacketData, []byte("hello"), 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	// type-id должен попадать в Data диапазон
	typeID := binary.BigEndian.Uint32(raw[:4])
	if !hc.Data.Contains(typeID) {
		t.Fatalf("type-id 0x%08x not in Data range [0x%08x, 0x%08x]",
			typeID, hc.Data.Min, hc.Data.Max)
	}
	// Декодируем
	pkt, err := decodePacket(dec, &hc, raw)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != PacketData {
		t.Fatalf("wrong type: %v", pkt.Type)
	}
	if string(pkt.Payload) != "hello" {
		t.Fatal("payload mismatch")
	}
}

func TestRangeHeadersAllTypes(t *testing.T) {
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	for i := range key {
		key[i] = byte(i + 1)
	}
	hc := DefaultHeaderConfig()
	types := []PacketType{PacketData, PacketKeepalive, PacketNoise, PacketHandshake, PacketClose}

	for _, pt := range types {
		enc, _ := NewCipher(key, iv)
		dec, _ := NewCipher(key, iv)
		raw, err := encodePacket(enc, &hc, pt, []byte("test"), 0, 8)
		if err != nil {
			t.Fatalf("encode %v: %v", pt, err)
		}
		pkt, err := decodePacket(dec, &hc, raw)
		if err != nil {
			t.Fatalf("decode %v: %v", pt, err)
		}
		if pkt.Type != pt {
			t.Fatalf("type mismatch: got %v, want %v", pkt.Type, pt)
		}
	}
}

func TestRangeHeadersTypeIDVaries(t *testing.T) {
	key := [KeySize]byte{}
	iv := [NonceSize]byte{}
	hc := DefaultHeaderConfig()
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		enc, _ := NewCipher(key, iv)
		raw, _ := encodePacket(enc, &hc, PacketData, []byte("x"), 0, 4)
		typeID := binary.BigEndian.Uint32(raw[:4])
		seen[typeID] = true
	}
	if len(seen) < 5 {
		t.Fatal("type-id should vary across packets")
	}
}
