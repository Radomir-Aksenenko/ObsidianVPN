package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

// Socks5Proxy is a lightweight local SOCKS5 proxy server.
// It allows client applications (browsers, apps, mobile WebViews, curl)
// to route traffic through the active Obsidian VPN tunnel via 127.0.0.1:port.
type Socks5Proxy struct {
	listener net.Listener
	closed   chan struct{}
	once     sync.Once
}

// StartSocks5Proxy starts a local SOCKS5 server listening on listenAddr (e.g. "127.0.0.1:10808").
func StartSocks5Proxy(listenAddr string) (*Socks5Proxy, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen socks5: %w", err)
	}

	p := &Socks5Proxy{
		listener: ln,
		closed:   make(chan struct{}),
	}

	go p.serve()
	return p, nil
}

// Addr returns the listener address.
func (p *Socks5Proxy) Addr() net.Addr {
	return p.listener.Addr()
}

// Close terminates the proxy.
func (p *Socks5Proxy) Close() error {
	p.once.Do(func() {
		close(p.closed)
		p.listener.Close()
	})
	return nil
}

func (p *Socks5Proxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
				continue
			}
		}
		go p.handleConn(conn)
	}
}

func (p *Socks5Proxy) handleConn(client net.Conn) {
	defer client.Close()

	// 1. Negotiation
	// [VER, NMETHODS, METHODS...]
	header := make([]byte, 2)
	if _, err := io.ReadFull(client, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return // only SOCKS5
	}
	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	// Reply: NO AUTH (0x00)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request
	// [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(client, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 { // 0x01 = CONNECT
		// Send Command Not Supported (0x07)
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetHost string
	atyp := reqHeader[3]
	switch atyp {
	case 0x01: // IPv4 (4 bytes)
		ip := make([]byte, 4)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()
	case 0x03: // Domain name (1 byte len + string)
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(client, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(client, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 0x04: // IPv6 (16 bytes)
		ip := make([]byte, 16)
		if _, err := io.ReadFull(client, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()
	default:
		// Address type not supported
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(client, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

	// Dial target
	remote, err := net.Dial("tcp", targetAddr)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Host unreachable
		return
	}
	defer remote.Close()

	// Reply SUCCESS (0x00)
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Bidirectional forward
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, client)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(client, remote)
		errCh <- err
	}()
	<-errCh
}
