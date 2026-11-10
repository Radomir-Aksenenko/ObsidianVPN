package obsidian

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

const rekeyLabel = "obsidian_rekey_v1"

// DeriveRekeyedKeys derives the keys of the next epoch from a fresh hybrid exchange made inside
// the tunnel. The fresh X25519 and ML-KEM secrets are the input key material and the old
// ChainKey is the salt:
//
//	prk  = HKDF-Extract(salt = old.ChainKey, ikm = ss_x25519 || ss_mlkem)
//	keys = HKDF-Expand(prk, "obsidian_rekey_v1" || epoch || SHA-256(transcript))
//
// Mixing in the old ChainKey keeps the new keys bound to the authenticated session; the fresh
// exchange means an attacker who stole the old keys but only watches the traffic does not learn
// the new ones (post-compromise security). A hash-only ratchet would not give that.
func DeriveRekeyedKeys(old *SessionKeys, epoch uint32, ssX25519, ssMLKEM, transcript []byte) (*SessionKeys, error) {
	if old == nil {
		return nil, errors.New("nil session keys")
	}
	if len(ssX25519) != KeySize || len(ssMLKEM) != MLKEM768SharedKeySize {
		return nil, errors.New("invalid rekey shared secret size")
	}
	ikm := make([]byte, 0, len(ssX25519)+len(ssMLKEM))
	ikm = append(ikm, ssX25519...)
	ikm = append(ikm, ssMLKEM...)
	prk := hkdf.Extract(sha256.New, ikm, old.ChainKey[:])
	clear(ikm)

	th := sha256.Sum256(transcript)
	info := make([]byte, 0, len(rekeyLabel)+4+len(th))
	info = append(info, rekeyLabel...)
	info = binary.BigEndian.AppendUint32(info, epoch)
	info = append(info, th[:]...)

	buf := make([]byte, sessionKeyMaterialSize)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, info), buf); err != nil {
		return nil, err
	}
	clear(prk)
	sk := &SessionKeys{}
	copy(sk.ClientKey[:], buf[0:32])
	copy(sk.ServerKey[:], buf[32:64])
	copy(sk.ClientIV[:], buf[64:76])
	copy(sk.ServerIV[:], buf[76:88])
	copy(sk.SessionID[:], buf[88:104])
	copy(sk.DynamicMagic[:], buf[104:120])
	copy(sk.ChainKey[:], buf[120:152])
	clear(buf)
	return sk, nil
}
