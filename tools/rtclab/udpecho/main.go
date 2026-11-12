// Command udpecho is the voice server of tools/rtclab: UDP echo, Discord IP discovery replies and large replies on request.
package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
)

func main() {
	c, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 65535)
	for {
		n, a, err := c.ReadFrom(buf)
		if err != nil {
			continue
		}
		p := buf[:n]
		// Discord IP discovery: type 0x1 length 70 ssrc(4) addr(64) port(2) -> reply type 0x2 with the address seen.
		if n == 74 && binary.BigEndian.Uint16(p[0:2]) == 1 && binary.BigEndian.Uint16(p[2:4]) == 70 {
			r := make([]byte, 74)
			binary.BigEndian.PutUint16(r[0:2], 2)
			binary.BigEndian.PutUint16(r[2:4], 70)
			copy(r[4:8], p[4:8])
			ua := a.(*net.UDPAddr)
			copy(r[8:72], ua.IP.String())
			binary.BigEndian.PutUint16(r[72:74], uint16(ua.Port))
			c.WriteTo(r, a)
			continue
		}
		// "BIG:<n>" asks for an n-byte reply (DTLS certificate flights, video keyframes).
		if n >= 4 && string(p[:4]) == "BIG:" {
			var sz int
			for _, ch := range p[4:] {
				if ch < '0' || ch > '9' {
					break
				}
				sz = sz*10 + int(ch-'0')
			}
			if sz > 0 && sz < 65000 {
				c.WriteTo(make([]byte, sz), a)
			}
			continue
		}
		c.WriteTo(p, a)
	}
}
