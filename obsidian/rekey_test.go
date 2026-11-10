package obsidian

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSessionKeys(t *testing.T) *SessionKeys {
	t.Helper()
	sk, err := DeriveKeys([KeySize]byte{9}, []byte("salt"), [KeySize]byte{1}, [KeySize]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	return sk
}

var fastRekey = RekeyConfig{Interval: 40 * time.Millisecond, Timeout: 2 * time.Second, Grace: 20 * time.Millisecond, MinInterval: time.Millisecond, AnnounceWithin: 30 * time.Millisecond}

// streamUntil sends numbered DATA packets from src until stop closes and checks on dst that
// every one arrives, in order. It returns how many were checked.
func streamUntil(t *testing.T, src, dst *Tunnel, stop <-chan struct{}, batch bool) (chan int, chan error) {
	sent := make(chan int, 1)
	errc := make(chan error, 2)
	go func() {
		i := 0
		for {
			select {
			case <-stop:
				sent <- i
				return
			default:
			}
			p := make([]byte, 60+i%900)
			binary.BigEndian.PutUint32(p, uint32(i))
			var err error
			if batch {
				_, err = src.SendDataBatch([][]byte{p, append([]byte(nil), p...)})
				i++
			} else {
				err = src.SendData(p)
			}
			if err != nil {
				errc <- err
				sent <- i
				return
			}
			i++
		}
	}()
	return sent, errc
}

func recvNumbered(t *testing.T, dst *Tunnel, n int, batch bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := make([]byte, 4096)
	for i := 0; i < n; i++ {
		m, err := dst.RecvDataInto(ctx, buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		want := i
		if batch {
			want = i &^ 1 // each batch carries the same number twice
		}
		if m < 4 || int(binary.BigEndian.Uint32(buf)) != want {
			t.Fatalf("packet %d: got #%d", i, binary.BigEndian.Uint32(buf))
		}
	}
}

// Data keeps flowing both ways, unchanged and in order, while the keys change several times.
func TestRekeyKeepsTrafficFlowing(t *testing.T) {
	client, server := newTunnelPair(t, nil)
	sk := testSessionKeys(t)
	var accepts, srvCommits, cliCommits, drops atomic.Int32
	if err := server.EnableRekey(sk, false, fastRekey, RekeyHooks{
		AcceptNext: func(*SessionKeys) error { accepts.Add(1); return nil },
		Commit:     func(*SessionKeys) error { srvCommits.Add(1); return nil },
		DropPrev:   func() { drops.Add(1) },
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.EnableRekey(sk, true, fastRekey, RekeyHooks{
		Commit: func(*SessionKeys) error { cliCommits.Add(1); return nil },
	}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	upSent, upErr := streamUntil(t, client, server, stop, false)
	downSent, downErr := streamUntil(t, server, client, stop, true)

	var wg sync.WaitGroup
	var upGot, downGot atomic.Int64
	done := make(chan struct{})
	recv := func(dst *Tunnel, got *atomic.Int64, batch bool) {
		defer wg.Done()
		buf := make([]byte, 4096)
		for i := 0; ; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			m, err := dst.RecvDataInto(ctx, buf)
			cancel()
			if err != nil {
				return
			}
			want := i
			if batch {
				want = i &^ 1
			}
			if m < 4 || int(binary.BigEndian.Uint32(buf)) != want {
				t.Errorf("packet %d arrived as #%d", i, binary.BigEndian.Uint32(buf))
				return
			}
			got.Store(int64(i + 1))
			select {
			case <-done:
				return
			default:
			}
		}
	}
	wg.Add(2)
	go recv(server, &upGot, false)
	go recv(client, &downGot, true)

	deadline := time.Now().Add(10 * time.Second)
	for (client.RekeyEpoch() < 3 || server.RekeyEpoch() < 3) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	up, down := <-upSent, <-downSent
	select {
	case err := <-upErr:
		t.Fatalf("uplink send: %v", err)
	case err := <-downErr:
		t.Fatalf("downlink send: %v", err)
	default:
	}
	for time.Now().Before(deadline) && (upGot.Load() < int64(up) || downGot.Load() < int64(down)) {
		time.Sleep(5 * time.Millisecond)
	}
	close(done)
	if upGot.Load() < int64(up) || downGot.Load() < int64(down) {
		t.Fatalf("lost packets: up %d/%d down %d/%d", upGot.Load(), up, downGot.Load(), down)
	}
	if e := client.RekeyEpoch(); e < 3 {
		t.Fatalf("client reached epoch %d", e)
	}
	if accepts.Load() < 3 || srvCommits.Load() < 3 || cliCommits.Load() < 3 {
		t.Fatalf("hooks: accept %d server commit %d client commit %d", accepts.Load(), srvCommits.Load(), cliCommits.Load())
	}
	time.Sleep(50 * time.Millisecond)
	if drops.Load() < 1 {
		t.Fatal("previous epoch was never dropped")
	}
	select {
	case <-client.Done():
		t.Fatal("client tunnel closed")
	case <-server.Done():
		t.Fatal("server tunnel closed")
	default:
	}
}

// The new keys depend on the fresh exchange: two rekeys from the same old keys give different
// keys, and both peers agree on them.
func TestRekeyProducesFreshAgreedKeys(t *testing.T) {
	client, server := newTunnelPair(t, nil)
	sk := testSessionKeys(t)
	var cliKeys, srvKeys *SessionKeys
	var mu sync.Mutex
	_ = server.EnableRekey(sk, false, fastRekey, RekeyHooks{Commit: func(k *SessionKeys) error {
		mu.Lock()
		srvKeys = k
		mu.Unlock()
		return nil
	}})
	_ = client.EnableRekey(sk, true, fastRekey, RekeyHooks{Commit: func(k *SessionKeys) error {
		mu.Lock()
		cliKeys = k
		mu.Unlock()
		return nil
	}})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := cliKeys != nil && srvKeys != nil
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if cliKeys == nil || srvKeys == nil {
		t.Fatal("rekey did not complete")
	}
	if cliKeys.ClientKey != srvKeys.ClientKey || cliKeys.ChainKey != srvKeys.ChainKey {
		t.Fatal("peers derived different keys")
	}
	if cliKeys.ClientKey == sk.ClientKey || cliKeys.SessionID == sk.SessionID {
		t.Fatal("keys did not change")
	}
}

// An older server never announces support, so the client must not send PacketRekey to it; an
// older client ignores the announcement. Both keep working.
func TestRekeyCompatibleWithOlderPeers(t *testing.T) {
	t.Run("old server", func(t *testing.T) {
		client, server := newTunnelPair(t, nil)
		_ = client.EnableRekey(testSessionKeys(t), true, fastRekey, RekeyHooks{})
		time.Sleep(200 * time.Millisecond)
		if client.RekeyEpoch() != 0 {
			t.Fatal("client rekeyed with a server that never announced support")
		}
		go func() { _ = client.SendData([]byte("after")) }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		buf := make([]byte, 64)
		if n, err := server.RecvDataInto(ctx, buf); err != nil || string(buf[:n]) != "after" {
			t.Fatalf("tunnel broken: %v", err)
		}
	})
	t.Run("old client", func(t *testing.T) {
		client, server := newTunnelPair(t, nil)
		if err := server.EnableRekey(testSessionKeys(t), false, fastRekey, RekeyHooks{}); err != nil {
			t.Fatal(err)
		}
		go func() { _ = server.SendData([]byte("hello")) }()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		buf := make([]byte, 64)
		if n, err := client.RecvDataInto(ctx, buf); err != nil || string(buf[:n]) != "hello" {
			t.Fatalf("old client broke on the announcement: %v", err)
		}
	})
}

// Out-of-order or malformed rekey messages close the tunnel instead of being ignored.
func TestRekeyRejectsProtocolViolations(t *testing.T) {
	sk := testSessionKeys(t)
	mk := func(isClient bool) *Tunnel {
		client, server := newTunnelPair(t, nil)
		tun := server
		if isClient {
			tun = client
		}
		if err := tun.EnableRekey(sk, isClient, fastRekey, RekeyHooks{}); err != nil {
			t.Fatal(err)
		}
		return tun
	}
	fin := binary.BigEndian.AppendUint32([]byte{rekeyMsgFin}, 1)
	if err := mk(false).handleRekey(fin); err == nil {
		t.Error("server accepted FIN without INIT")
	}
	resp := make([]byte, rekeyRespLen)
	resp[0] = rekeyMsgResp
	binary.BigEndian.PutUint32(resp[1:], 1)
	if err := mk(true).handleRekey(resp); err == nil {
		t.Error("client accepted RESP it never asked for")
	}
	init := make([]byte, rekeyInitLen)
	init[0] = rekeyMsgInit
	binary.BigEndian.PutUint32(init[1:], 5)
	if err := mk(false).handleRekey(init); err == nil {
		t.Error("server accepted a skipped epoch")
	}
	if err := mk(false).handleRekey(init[:100]); err == nil {
		t.Error("server accepted a truncated INIT")
	}
	if err := mk(true).handleRekey(init); err == nil {
		t.Error("client accepted INIT")
	}
	tun, _ := newTunnelPair(t, nil)
	if err := tun.handleRekey(fin); err == nil {
		t.Error("tunnel without rekey accepted a rekey message")
	}
}

// A server that receives PacketRekey without supporting it closes the tunnel; the client then
// sees it closed rather than hanging.
func TestRekeyWithoutServerSupportClosesTunnel(t *testing.T) {
	client, _ := newTunnelPair(t, nil)
	_ = client.EnableRekey(testSessionKeys(t), true, fastRekey, RekeyHooks{})
	client.noteNoise(append(append([]byte(nil), rekeyCapMagic...), 1, 2, 3))
	select {
	case <-client.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client kept a tunnel the server dropped")
	}
}

// Over real UDP sockets, wired the way client and server wire their hooks: datagrams keep
// arriving both ways across rekeys, and the previous epoch is refused after the grace period.
func TestRekeyMovesUDPAlong(t *testing.T) {
	sk := testSessionKeys(t)
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srvConn.Close()
	cliConn, err := net.DialUDP("udp", nil, srvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer cliConn.Close()
	ch, err := NewUDPChannel(cliConn, DeriveUDPKeys(sk, true))
	if err != nil {
		t.Fatal(err)
	}
	mux := NewUDPMux(srvConn)
	sess, err := mux.RegisterSession(DeriveUDPKeys(sk, false))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	go mux.Run()

	client, server := newTunnelPair(t, nil)
	cfg := fastRekey
	cfg.Interval, cfg.Grace = 150*time.Millisecond, 50*time.Millisecond
	_ = server.EnableRekey(sk, false, cfg, RekeyHooks{
		AcceptNext: func(k *SessionKeys) error { return sess.AcceptEpoch(DeriveUDPKeys(k, false)) },
		Commit:     func(k *SessionKeys) error { return sess.CommitSendEpoch(DeriveUDPKeys(k, false)) },
		DropPrev:   sess.DropPrevEpoch,
	})
	_ = client.EnableRekey(sk, true, cfg, RekeyHooks{
		Commit:   func(k *SessionKeys) error { return ch.RatchetEpoch(DeriveUDPKeys(k, true)) },
		DropPrev: ch.DropPrevEpoch,
	})

	echo := func(i int) {
		t.Helper()
		msg := []byte{byte(i), byte(i >> 8), 'u'}
		if err := ch.Send(msg); err != nil {
			t.Fatal(err)
		}
		got, err := recvWithTimeout(sess)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("uplink %d: %v", i, err)
		}
		PutPacket(got)
		reply := []byte{byte(i), byte(i >> 8), 'd'}
		if err := sess.Send(reply); err != nil {
			t.Fatal(err)
		}
		_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 64)
		n, err := ch.Recv(buf)
		if err != nil || !bytes.Equal(buf[:n], reply) {
			t.Fatalf("downlink %d: %v", i, err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	i := 0
	for client.RekeyEpoch() < 3 && time.Now().Before(deadline) {
		echo(i)
		i++
		time.Sleep(2 * time.Millisecond)
	}
	if client.RekeyEpoch() < 3 {
		t.Fatalf("only %d rekeys", client.RekeyEpoch())
	}
	// Let the grace period pass, then a datagram sealed with epoch-0 keys must be refused.
	time.Sleep(200 * time.Millisecond)
	old, err := NewUDPChannel(cliConn, DeriveUDPKeys(sk, true))
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Send([]byte("stale")); err != nil {
		t.Fatal(err)
	}
	echo(i)
	if rk := sess.recv.Load(); rk.prevDec != nil {
		// A rekey may have just happened; the stale epoch is never the previous one by now.
		if rk.prevTag == DeriveUDPKeys(sk, false).SessionTag {
			t.Fatal("epoch 0 still accepted")
		}
	}
	if len(sess.dataIn) != 0 {
		t.Fatal("stale datagram was accepted")
	}
}

func recvWithTimeout(s *UDPSession) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	c := make(chan res, 1)
	go func() { b, err := s.Recv(); c <- res{b, err} }()
	select {
	case r := <-c:
		return r.b, r.err
	case <-time.After(2 * time.Second):
		return nil, context.DeadlineExceeded
	}
}

// The announcement goes out at a random moment, not right after the handshake, and a client that
// enables rekey before it arrives still picks it up.
func TestRekeyAnnouncementIsDelayed(t *testing.T) {
	client, server := newTunnelPair(t, nil)
	if err := client.EnableRekey(testSessionKeys(t), true, fastRekey, RekeyHooks{}); err != nil {
		t.Fatal(err)
	}
	cfg := fastRekey
	cfg.AnnounceWithin = 300 * time.Millisecond
	start := time.Now()
	if err := server.EnableRekey(testSessionKeys(t), false, cfg, RekeyHooks{}); err != nil {
		t.Fatal(err)
	}
	if client.peerRekeyCapable.Load() {
		t.Fatal("announcement was sent synchronously")
	}
	deadline := time.Now().Add(5 * time.Second)
	for client.RekeyEpoch() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if client.RekeyEpoch() == 0 {
		t.Fatal("client never rekeyed after a late announcement")
	}
	if time.Since(start) < cfg.AnnounceWithin/30 {
		t.Fatal("announcement came before its earliest moment")
	}
}

// Rekey messages must not have a fixed size on the wire: each one carries random padding and a
// NOISE frame of random size.
func TestRekeyFramesVaryInSize(t *testing.T) {
	cli, _ := newTunnelPair(t, nil)
	payload := make([]byte, rekeyInitLen)
	buf := make([]byte, len(payload)+rekeyFrameSlack)
	sizes := map[int]bool{}
	cli.sendMu.Lock()
	for i := 0; i < 32; i++ {
		n, err := cli.appendRekeyFrames(buf, payload)
		if err != nil {
			cli.sendMu.Unlock()
			t.Fatal(err)
		}
		if n <= len(payload) {
			cli.sendMu.Unlock()
			t.Fatalf("frame of %d bytes is not larger than its %d byte payload", n, len(payload))
		}
		sizes[n] = true
	}
	cli.sendMu.Unlock()
	if len(sizes) < 8 {
		t.Fatalf("only %d distinct sizes in 32 rekey frames", len(sizes))
	}
}
