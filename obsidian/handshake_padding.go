package obsidian

import (
	"math/rand/v2"
	"time"
)

// Padding for encapsulated TLS handshakes.
//
// The outer TLS hides content, not sizes. The user's own TLS handshakes inside the tunnel (a
// ClientHello of about 517 bytes, the server's first flight) still show up as a recognizable run
// of record sizes and directions; Xue et al., "Fingerprinting Obfuscated Proxy Traffic with
// Encapsulated TLS Handshakes" (USENIX Security 2024) classify proxies by exactly that.
//
// A DATA packet that carries the start of a TLS handshake record gets random padding and is
// followed, in the same write, by a NOISE frame of random size. Both already exist in the wire
// format and every core discards them, so only the sender changes. Bulk data is untouched: only
// TCP segments whose payload starts with a TLS handshake record header qualify, a few per
// connection. A byte budget caps the cost even under a storm of new connections.

const (
	hsPadMin      = 64
	hsPadMax      = 256 // exclusive; PAD_LEN is one byte
	hsNoiseMin    = 64
	hsNoiseMax    = 512 // exclusive
	hsBudgetBurst = 32 * 1024
	hsBudgetRate  = 1024 // bytes per second
)

// handshakePadBudget is a token bucket of padding bytes. Callers hold Tunnel.sendMu.
type handshakePadBudget struct {
	tokens float64
	at     time.Time
}

func (b *handshakePadBudget) take(cost int, now time.Time) bool {
	if b.at.IsZero() {
		b.tokens, b.at = hsBudgetBurst, now
	}
	b.tokens += now.Sub(b.at).Seconds() * hsBudgetRate
	if b.tokens > hsBudgetBurst {
		b.tokens = hsBudgetBurst
	}
	b.at = now
	if b.tokens < float64(cost) {
		return false
	}
	b.tokens -= float64(cost)
	return true
}

// handshakePadPlan picks padding and the NOISE payload size for one handshake packet.
func handshakePadPlan() (pad, noise int) {
	return hsPadMin + rand.IntN(hsPadMax-hsPadMin), hsNoiseMin + rand.IntN(hsNoiseMax-hsNoiseMin)
}

// LooksLikeTLSHandshake reports whether pkt is an IPv4 or IPv6 TCP segment whose payload starts
// with a TLS handshake record header (type 0x16, version 3.x). IPv6 extension headers are not
// followed; such packets simply go unpadded.
func LooksLikeTLSHandshake(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	var tcp []byte
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 || pkt[9] != 6 {
			return false
		}
		if frag := uint16(pkt[6]&0x1f)<<8 | uint16(pkt[7]); frag != 0 {
			return false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return false
		}
		tcp = pkt[ihl:]
	case 6:
		if len(pkt) < 40 || pkt[6] != 6 {
			return false
		}
		tcp = pkt[40:]
	default:
		return false
	}
	if len(tcp) < 20 {
		return false
	}
	off := int(tcp[12]>>4) * 4
	if off < 20 || len(tcp) < off+5 {
		return false
	}
	rec := tcp[off:]
	return rec[0] == 0x16 && rec[1] == 0x03 && rec[2] <= 0x04
}
