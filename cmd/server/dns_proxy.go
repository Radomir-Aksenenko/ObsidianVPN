package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dnsProxyTimeout  = 5 * time.Second
	maxConcurrentDNS = 512
)

var (
	dnsBufPool = sync.Pool{
		New: func() any {
			b := make([]byte, 4096)
			return &b
		},
	}
	dnsSem = make(chan struct{}, maxConcurrentDNS)
)

func getDNSBuf() []byte {
	p := dnsBufPool.Get().(*[]byte)
	return (*p)[:cap(*p)]
}

func putDNSBuf(b []byte) {
	if cap(b) >= 4096 {
		dnsBufPool.Put(&b)
	}
}

func startDNSProxy(cfg Config) error {
	addr := dnsListenAddress(cfg)
	if addr == "" {
		return fmt.Errorf("cannot derive DNS listen address from tun_address %q", cfg.TunAddress)
	}

	upstream := withDNSPort(cfg.DNSUpstream)
	if upstream == "" {
		upstream = detectDNSUpstream()
	}
	if upstream == "" {
		upstream = "9.9.9.9:53"
	}

	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", addr, err)
	}
	go serveDNSUDP(udp, upstream)

	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Printf("DNS TCP proxy unavailable on %s: %v", addr, err)
	} else {
		go serveDNSTCP(tcp, upstream)
	}

	log.Printf("DNS proxy listening on %s, upstream=%s", addr, upstream)
	return nil
}

func serveDNSUDP(pc net.PacketConn, upstream string) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("DNS udp read: %v", err)
			return
		}
		query := append([]byte(nil), buf[:n]...)

		select {
		case dnsSem <- struct{}{}:
			go func() {
				defer func() { <-dnsSem }()
				resp, err := exchangeDNSUDP(upstream, query)
				if err != nil {
					log.Printf("DNS udp upstream: %v", err)
					return
				}
				if _, err := pc.WriteTo(resp, addr); err != nil {
					log.Printf("DNS udp write: %v", err)
				}
				putDNSBuf(resp)
			}()
		default:
			log.Printf("DNS proxy saturated, dropping query from %s", addr)
		}
	}
}

func exchangeDNSUDP(upstream string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp4", upstream, dnsProxyTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(dnsProxyTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	resp := getDNSBuf()
	n, err := conn.Read(resp)
	if err != nil {
		putDNSBuf(resp)
		return nil, err
	}

	return resp[:n], nil
}

func serveDNSTCP(ln net.Listener, upstream string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("DNS tcp accept: %v", err)
			return
		}
		go proxyDNSTCP(conn, upstream)
	}
}

func proxyDNSTCP(client net.Conn, upstream string) {
	defer client.Close()
	server, err := net.DialTimeout("tcp4", upstream, dnsProxyTimeout)
	if err != nil {
		log.Printf("DNS tcp upstream: %v", err)
		return
	}
	defer server.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(server, client)
		_ = server.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, server)
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
}

func dnsListenAddress(cfg Config) string {
	listen := strings.TrimSpace(cfg.DNSListen)
	if listen == "" {
		listen = tunAddressIP(cfg.TunAddress)
	}
	if listen == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(listen); err == nil {
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(listen, "53")
}

func tunAddressIP(tunAddress string) string {
	prefix, err := netip.ParsePrefix(tunAddress)
	if err != nil {
		return ""
	}
	return prefix.Addr().String()
}

func detectDNSUpstream() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || !addr.Is4() || addr.IsUnspecified() {
			continue
		}
		return net.JoinHostPort(addr.String(), "53")
	}
	return ""
}

func withDNSPort(addr string) string {
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "53")
}
