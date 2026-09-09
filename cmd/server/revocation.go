package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"obsidian/obsidian"
)

// revocationStore applies a static deny list and, optionally, a file maintained
// by the key server. The file is reloaded when it changes, so revocation takes
// effect for new handshakes without restarting the VPN service.
type revocationStore struct {
	path string

	mu          sync.Mutex
	keys        map[[obsidian.KeySize]byte]struct{}
	modTime     time.Time
	initialized bool
}

type revocationFile struct {
	RevokedClients []string `json:"revoked_clients"`
}

func newRevocationStore(static []string, path string) (*revocationStore, error) {
	r := &revocationStore{path: path, keys: make(map[[obsidian.KeySize]byte]struct{})}
	if err := r.add(static); err != nil {
		return nil, err
	}
	if path != "" {
		if err := r.reload(true); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *revocationStore) IsRevoked(key [obsidian.KeySize]byte) bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.reload(false); err != nil {
		// Fail closed if an explicitly configured revocation file becomes
		// unreadable. Silently accepting a revoked key is worse than rejecting a
		// new session until the local key server is repaired.
		if !r.initialized {
			return false
		}
		return true
	}
	_, found := r.keys[key]
	return found
}

func (r *revocationStore) reload(force bool) error {
	if r.path == "" {
		return nil
	}
	info, err := os.Stat(r.path)
	if os.IsNotExist(err) {
		if force {
			return nil
		}
		return fmt.Errorf("revocation file %q is missing", r.path)
	}
	if err != nil {
		return err
	}
	if !force && !info.ModTime().After(r.modTime) {
		return nil
	}
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	var file revocationFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	keys := make(map[[obsidian.KeySize]byte]struct{})
	if err := addRevokedKeys(keys, file.RevokedClients); err != nil {
		return err
	}
	// Keep static configuration entries even after file reload.
	for key := range r.keys {
		keys[key] = struct{}{}
	}
	r.keys = keys
	r.modTime = info.ModTime().Truncate(time.Second)
	r.initialized = true
	return nil
}

func (r *revocationStore) add(values []string) error {
	return addRevokedKeys(r.keys, values)
}

func addRevokedKeys(dst map[[obsidian.KeySize]byte]struct{}, values []string) error {
	for _, value := range values {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != obsidian.KeySize {
			return fmt.Errorf("invalid revoked client key")
		}
		var key [obsidian.KeySize]byte
		copy(key[:], decoded)
		dst[key] = struct{}{}
	}
	return nil
}
