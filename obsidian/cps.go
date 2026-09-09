package obsidian

// ── CPS — Custom Protocol Signature ──────────────────────────────────────────
//
// Движок для генерации пакетов имитирующих легитимные протоколы (QUIC, DNS, SIP).
// Синтаксис тегов (как в AmneziaWG 2.0):
//
//   <b 0xHEX>   — вставить точные байты (hex без пробелов)
//   <t>         — 4-байтовый Unix timestamp (little-endian, как в реальных протоколах)
//   <r N>       — N полностью случайных байт
//   <rc N>      — N случайных буквенно-цифровых символов [A-Za-z0-9]
//   <rd N>      — N случайных цифровых символов [0-9]
//
// Примеры сигнатур:
//
//   QUIC Initial:
//     <b 0xc700000001><rc 8><t><r 100>
//
//   DNS запрос (простой):
//     <b 0x0001010000010000000000000377777703636f6d0000010001><r 10>
//
//   SIP REGISTER:
//     <b 0x524547495354455220736970><rc 20><b 0x20534950><r 50>
//
// Пакеты отправляются перед каждым handshake (раз в ~2 минуты по умолчанию).
// DPI видит их как легитимный трафик и не анализирует следующие пакеты.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ── CPS Token ─────────────────────────────────────────────────────────────────

type cpsTokenKind int

const (
	tokenBytes     cpsTokenKind = iota // <b 0xHEX>
	tokenTime                          // <t>
	tokenRand                          // <r N>
	tokenRandAlnum                     // <rc N>
	tokenRandDigit                     // <rd N>
)

type cpsToken struct {
	kind   cpsTokenKind
	data   []byte // для tokenBytes
	length int    // для tokenRand, tokenRandAlnum, tokenRandDigit
}

// CPSSignature — скомпилированная сигнатура, готовая к генерации пакетов.
type CPSSignature struct {
	tokens []cpsToken
	raw    string // оригинальная строка (для отладки)
}

// ParseCPS разбирает строку CPS формата и возвращает скомпилированную сигнатуру.
// Возвращает ошибку если строка некорректна.
func ParseCPS(s string) (*CPSSignature, error) {
	sig := &CPSSignature{raw: s}
	rest := strings.TrimSpace(s)

	for len(rest) > 0 {
		if rest[0] != '<' {
			return nil, fmt.Errorf("CPS: expected '<', got %q at: %s", rest[0], truncate(rest, 32))
		}
		end := strings.IndexByte(rest, '>')
		if end < 0 {
			return nil, fmt.Errorf("CPS: unclosed tag: %s", truncate(rest, 32))
		}
		tag := rest[1:end]
		rest = strings.TrimSpace(rest[end+1:])

		tok, err := parseTag(tag)
		if err != nil {
			return nil, err
		}
		sig.tokens = append(sig.tokens, tok)
	}

	if len(sig.tokens) == 0 {
		return nil, fmt.Errorf("CPS: empty signature")
	}
	return sig, nil
}

func parseTag(tag string) (cpsToken, error) {
	tag = strings.TrimSpace(tag)

	switch {
	case tag == "t":
		return cpsToken{kind: tokenTime}, nil

	case strings.HasPrefix(tag, "b "):
		hexStr := strings.TrimPrefix(tag, "b ")
		hexStr = strings.TrimPrefix(hexStr, "0x")
		hexStr = strings.ReplaceAll(hexStr, " ", "")
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return cpsToken{}, fmt.Errorf("CPS <b>: invalid hex %q: %w", hexStr, err)
		}
		return cpsToken{kind: tokenBytes, data: b}, nil

	case strings.HasPrefix(tag, "rc "):
		n, err := parseN(strings.TrimPrefix(tag, "rc "))
		if err != nil {
			return cpsToken{}, fmt.Errorf("CPS <rc>: %w", err)
		}
		return cpsToken{kind: tokenRandAlnum, length: n}, nil

	case strings.HasPrefix(tag, "rd "):
		n, err := parseN(strings.TrimPrefix(tag, "rd "))
		if err != nil {
			return cpsToken{}, fmt.Errorf("CPS <rd>: %w", err)
		}
		return cpsToken{kind: tokenRandDigit, length: n}, nil

	case strings.HasPrefix(tag, "r "):
		n, err := parseN(strings.TrimPrefix(tag, "r "))
		if err != nil {
			return cpsToken{}, fmt.Errorf("CPS <r>: %w", err)
		}
		return cpsToken{kind: tokenRand, length: n}, nil

	default:
		return cpsToken{}, fmt.Errorf("CPS: unknown tag %q", tag)
	}
}

func parseN(s string) (int, error) {
	s = strings.TrimSpace(s)
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("expected integer, got %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return 0, fmt.Errorf("length must be > 0, got %d", n)
	}
	if n > 65535 {
		return 0, fmt.Errorf("length too large: %d", n)
	}
	return n, nil
}

// ── Packet generation ─────────────────────────────────────────────────────────

const alnumChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const digitChars = "0123456789"

// Generate создаёт один пакет по сигнатуре.
func (sig *CPSSignature) Generate() ([]byte, error) {
	var out []byte
	for _, tok := range sig.tokens {
		chunk, err := tok.generate()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

func (tok *cpsToken) generate() ([]byte, error) {
	switch tok.kind {
	case tokenBytes:
		b := make([]byte, len(tok.data))
		copy(b, tok.data)
		return b, nil

	case tokenTime:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(time.Now().Unix()))
		return b, nil

	case tokenRand:
		return RandomBytes(tok.length)

	case tokenRandAlnum:
		return randomCharset(tok.length, alnumChars)

	case tokenRandDigit:
		return randomCharset(tok.length, digitChars)
	}
	return nil, fmt.Errorf("unknown token kind: %d", tok.kind)
}

func randomCharset(n int, charset string) ([]byte, error) {
	rb, err := RandomBytes(n)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	csLen := byte(len(charset))
	for i := range out {
		out[i] = charset[rb[i]%csLen]
	}
	return out, nil
}

// String возвращает оригинальную строку сигнатуры.
func (sig *CPSSignature) String() string { return sig.raw }

// ── Built-in signature presets ────────────────────────────────────────────────
// Готовые сигнатуры для быстрого старта.

// PresetQUIC — имитация QUIC Initial пакета (HTTP/3).
// В соответствии с RFC 9000 §14.1 размер полезной нагрузки QUIC Initial пакета
// ОБЯЗАН быть не менее 1200 байт (Padding / Crypto frames).
const PresetQUIC = `<b 0xc00000000108><rc 8><b 0x08><rc 8><b 0x0044b000000001><r 1170>`

// PresetDNS — имитация валидного DNS запроса типа A (RFC 1035 / RFC 6891 EDNS0).
const PresetDNS = `<r 2><b 0x010000010000000000010377777706676f6f676c6503636f6d00000100010000291000000000000000>`

// PresetSIP — имитация SIP REGISTER запроса.
// "REGISTER sip:" в ASCII = 0x524547495354455220736970 3a
const PresetSIP = `<b 0x524547495354455220736970><rc 12><b 0x20534950 2f322e30><r 80>`

// PresetSTUN — имитация STUN Binding Request (RFC 5389 / WebRTC).
// Magic cookie 0x2112A442 — обязательный для STUN
const PresetSTUN = `<b 0x000100002112a442><r 12>`

// ── Helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
