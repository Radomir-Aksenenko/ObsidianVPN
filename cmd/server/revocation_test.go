package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"obsidian/obsidian"
)

func TestRevocationStoreReloadsKeyserverFile(t *testing.T) {
	kp, err := obsidian.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "revoked_clients.json")
	if err := os.WriteFile(path, []byte(`{"revoked_clients":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newRevocationStore(nil, path)
	if err != nil {
		t.Fatal(err)
	}
	if store.IsRevoked(kp.Public) {
		t.Fatal("fresh client must not be revoked")
	}
	entry := hex.EncodeToString(kp.Public[:])
	if err := os.WriteFile(path, []byte(`{"revoked_clients":["`+entry+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if !store.IsRevoked(kp.Public) {
		t.Fatal("server must deny a key written by the keyserver")
	}
}
