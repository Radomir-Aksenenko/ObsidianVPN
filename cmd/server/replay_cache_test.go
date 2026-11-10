package main

import (
	"testing"
	"time"

	"obsidian/obsidian"
)

// Pre-padding and S1 padding are not authenticated. A replay with one padding byte flipped must
// still hit the cache, and the modified hello must still be a valid one (or the test proves nothing).
func TestReplayCacheIgnoresPaddingChanges(t *testing.T) {
	server, _ := obsidian.GenerateKeypair()
	hs, err := obsidian.NewClientHandshake(server.Public)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := hs.BuildHello()
	if err != nil {
		t.Fatal(err)
	}
	cache := newHandshakeReplayCache(2 * time.Minute)
	key, ok := obsidian.ClientHelloReplayKey(hello)
	if !ok || cache.Seen(key) {
		t.Fatal("first hello must parse and be new")
	}

	replay := append([]byte(nil), hello...)
	replay[len(replay)-1] ^= 0xff // last byte of the S1 padding
	sh, err := obsidian.NewServerHandshake(server.Private, server.Public, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sh.ProcessClientHello(replay); err != nil {
		t.Fatalf("modified hello should still be accepted by the handshake: %v", err)
	}
	key2, ok := obsidian.ClientHelloReplayKey(replay)
	if !ok || !cache.Seen(key2) {
		t.Fatal("replay with changed padding passed the cache")
	}
}
