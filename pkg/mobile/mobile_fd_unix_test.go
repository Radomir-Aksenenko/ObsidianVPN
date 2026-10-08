//go:build unix

package mobile

import (
	"encoding/hex"
	"os"
	"syscall"
	"testing"

	"obsidian/obsidian"
)

// Start failures must close the TUN fd that Go took ownership of.
// syscall.Pipe is unix-only, so this file is excluded on Windows.
func TestStartTunnelFailureClosesFd(t *testing.T) {
	starts := map[string]func(fd int) (string, error){
		"WithFd bad uri": func(fd int) (string, error) {
			return StartTunnelWithFd("not-a-uri", fd, 1500, nil, nil, nil)
		},
		"WithConfig bad json": func(fd int) (string, error) {
			return StartTunnelWithConfig("{not json", fd, 1500, nil, nil, nil)
		},
	}

	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			var p [2]int
			if err := syscall.Pipe(p[:]); err != nil {
				t.Fatalf("pipe: %v", err)
			}
			rfd, wfd := p[0], p[1]
			w := os.NewFile(uintptr(wfd), "test-pipe-w")
			defer w.Close()

			sessID, err := start(rfd)
			if err == nil {
				t.Fatal("expected error")
			}
			if sessID != "" {
				t.Fatalf("expected empty session ID on error, got %q", sessID)
			}

			// With the read end closed, a write must fail with EPIPE.
			// If it succeeds, the read end is still open and the fd leaked.
			if _, err := w.Write([]byte{0}); err == nil {
				t.Fatal("write succeeded: TUN fd was not closed on start failure")
			}
		})
	}
}

// A negative fd is rejected by tun.OpenFD with a valid config, so no session starts and nothing is closed.
func TestStartTunnelNegativeFdRejected(t *testing.T) {
	kp, _ := obsidian.GenerateKeypair()
	uri := obsidian.EncodeURI(&obsidian.ClientConfig{
		ServerPublicKey: hex.EncodeToString(kp.Public[:]),
		ServerHost:      "127.0.0.1",
		ServerPort:      "59998",
	}, "test")

	sessID, err := StartTunnelWithFd(uri, -1, 1500, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for negative fd")
	}
	if sessID != "" {
		t.Fatalf("expected empty session ID, got %q", sessID)
	}
}
