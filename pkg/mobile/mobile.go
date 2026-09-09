package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"obsidian/obsidian"
	"obsidian/obsidian/client"
	"obsidian/obsidian/tun"
)

// SocketProtector is implemented by mobile host applications (e.g. Android VpnService)
// to mark sockets as exempt from the VPN routing table before traffic is routed through them.
type SocketProtector interface {
	Protect(fd int) bool
}

// StatusListener receives state transitions (e.g. "connecting", "connected", "reconnecting", "disconnected").
type StatusListener interface {
	OnStatusChange(status string, detail string)
}

// StatsListener receives real-time throughput metrics.
type StatsListener interface {
	OnStats(bytesSent int64, bytesRecv int64, txSpeed int64, rxSpeed int64)
}

// MobileStats encapsulates snapshot statistics for Gomobile compatibility.
type MobileStats struct {
	Status      string
	BytesSent   int64
	BytesRecv   int64
	PacketsSent int64
	PacketsRecv int64
	TxSpeedBps  int64
	RxSpeedBps  int64
	ActiveProto string
}

type activeSessionHolder struct {
	session   *client.Session
	dev       tun.Device
	packetDev *tun.PacketDevice
}

var (
	sessionMu       sync.Mutex
	activeSessions  = make(map[string]*activeSessionHolder)
	globalProxyMu   sync.Mutex
	activeSocks5    *client.Socks5Proxy
	nextSessionID   int
)

// StartTunnelWithFd initializes and starts an Obsidian VPN tunnel using an OS-provided TUN file descriptor.
// This is the primary entry point for Android VpnService.
func StartTunnelWithFd(
	configURI string,
	tunFd int,
	mtu int,
	protector SocketProtector,
	statusListener StatusListener,
	statsListener StatsListener,
) (string, error) {
	cfg, err := obsidian.DecodeKey(configURI)
	if err != nil {
		return "", fmt.Errorf("decode URI: %w", err)
	}

	dev, err := tun.OpenFD(tunFd, "mobile-tun", mtu)
	if err != nil {
		return "", fmt.Errorf("open tun fd: %w", err)
	}

	return startTunnelSession(cfg, dev, nil, protector, statusListener, statsListener)
}

// StartTunnelWithConfig initializes a tunnel with a raw JSON configuration string.
func StartTunnelWithConfig(
	configJSON string,
	tunFd int,
	mtu int,
	protector SocketProtector,
	statusListener StatusListener,
	statsListener StatsListener,
) (string, error) {
	var cfg obsidian.ClientConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return "", fmt.Errorf("parse json config: %w", err)
	}

	dev, err := tun.OpenFD(tunFd, "mobile-tun", mtu)
	if err != nil {
		return "", fmt.Errorf("open tun fd: %w", err)
	}

	return startTunnelSession(&cfg, dev, nil, protector, statusListener, statsListener)
}

// StartPacketTunnel creates a tunnel that receives and delivers packets in-memory.
// Ideal for iOS NetworkExtension NEPacketTunnelProvider packetFlow.
func StartPacketTunnel(
	configURI string,
	mtu int,
	protector SocketProtector,
	statusListener StatusListener,
	statsListener StatsListener,
) (string, error) {
	cfg, err := obsidian.DecodeKey(configURI)
	if err != nil {
		return "", fmt.Errorf("decode URI: %w", err)
	}

	pktDev := tun.NewPacketDevice("ios-packet-tun", mtu, 2048)
	return startTunnelSession(cfg, pktDev, pktDev, protector, statusListener, statsListener)
}

func startTunnelSession(
	cfg *obsidian.ClientConfig,
	dev tun.Device,
	pktDev *tun.PacketDevice,
	protector SocketProtector,
	statusListener StatusListener,
	statsListener StatsListener,
) (string, error) {
	var opts []client.Option

	if protector != nil {
		opts = append(opts, client.WithSocketProtector(func(fd int) error {
			if !protector.Protect(fd) {
				return errors.New("mobile socket protection failed")
			}
			return nil
		}))
	}

	if statusListener != nil {
		opts = append(opts, client.WithStatusCallback(func(status, detail string) {
			statusListener.OnStatusChange(status, detail)
		}))
	}

	if statsListener != nil {
		opts = append(opts, client.WithStatsCallback(func(stats client.SessionStats) {
			statsListener.OnStats(
				int64(stats.BytesSent),
				int64(stats.BytesReceived),
				int64(stats.TxSpeedBps),
				int64(stats.RxSpeedBps),
			)
		}))
	}

	session, err := client.NewSession(cfg, opts...)
	if err != nil {
		dev.Close()
		return "", fmt.Errorf("init session: %w", err)
	}

	sessionMu.Lock()
	nextSessionID++
	id := fmt.Sprintf("sess-%d-%d", nextSessionID, time.Now().UnixNano())
	holder := &activeSessionHolder{
		session:   session,
		dev:       dev,
		packetDev: pktDev,
	}
	activeSessions[id] = holder
	sessionMu.Unlock()

	session.StartAsync(dev)
	return id, nil
}

// StopTunnel stops and cleans up an active mobile tunnel session.
func StopTunnel(sessionID string) error {
	sessionMu.Lock()
	holder, ok := activeSessions[sessionID]
	if ok {
		delete(activeSessions, sessionID)
	}
	sessionMu.Unlock()

	if !ok {
		return errors.New("session not found")
	}

	holder.session.Stop()
	if holder.dev != nil {
		_ = holder.dev.Close()
	}
	return nil
}

// GetStats returns current metrics for a session.
func GetStats(sessionID string) (*MobileStats, error) {
	sessionMu.Lock()
	holder, ok := activeSessions[sessionID]
	sessionMu.Unlock()

	if !ok {
		return nil, errors.New("session not found")
	}

	raw := holder.session.GetStats()
	return &MobileStats{
		Status:      raw.Status,
		BytesSent:   int64(raw.BytesSent),
		BytesRecv:   int64(raw.BytesReceived),
		PacketsSent: int64(raw.PacketsSent),
		PacketsRecv: int64(raw.PacketsReceived),
		TxSpeedBps:  int64(raw.TxSpeedBps),
		RxSpeedBps:  int64(raw.RxSpeedBps),
		ActiveProto: raw.ActiveDataProtocol,
	}, nil
}

// InjectPacket feeds an incoming IP packet from iOS packetFlow into the tunnel.
func InjectPacket(sessionID string, pkt []byte) error {
	sessionMu.Lock()
	holder, ok := activeSessions[sessionID]
	sessionMu.Unlock()

	if !ok || holder.packetDev == nil {
		return errors.New("packet tunnel session not found")
	}
	return holder.packetDev.InjectPacket(pkt)
}

// ReceivePacket reads the next outgoing IP packet to deliver to iOS packetFlow.
func ReceivePacket(sessionID string, timeoutMs int) ([]byte, error) {
	sessionMu.Lock()
	holder, ok := activeSessions[sessionID]
	sessionMu.Unlock()

	if !ok || holder.packetDev == nil {
		return nil, errors.New("packet tunnel session not found")
	}

	if timeoutMs <= 0 {
		timeoutMs = 1000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	return holder.packetDev.ReceivePacket(ctx)
}

// ParseConfigURI parses an Obsidian URI and returns the configuration formatted as JSON.
func ParseConfigURI(uri string) (string, error) {
	cfg, err := obsidian.DecodeKey(uri)
	if err != nil {
		return "", fmt.Errorf("decode URI: %w", err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal json: %w", err)
	}
	return string(data), nil
}

// StartLocalProxy starts a local SOCKS5 proxy server listening on listenAddr (e.g. "127.0.0.1:10808").
func StartLocalProxy(listenAddr string) error {
	globalProxyMu.Lock()
	defer globalProxyMu.Unlock()

	if activeSocks5 != nil {
		_ = activeSocks5.Close()
	}

	p, err := client.StartSocks5Proxy(listenAddr)
	if err != nil {
		return err
	}
	activeSocks5 = p
	return nil
}

// StopLocalProxy terminates the running local proxy.
func StopLocalProxy() error {
	globalProxyMu.Lock()
	defer globalProxyMu.Unlock()

	if activeSocks5 != nil {
		err := activeSocks5.Close()
		activeSocks5 = nil
		return err
	}
	return nil
}
