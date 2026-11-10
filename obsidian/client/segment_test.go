package client

import "encoding/binary"

// Copy of the obsidian package test helper: test files are not shared across packages.
type seg struct {
	v6       bool
	sport    uint16
	ack      uint32
	flags    byte
	payload  int
	sack     bool
	ts       bool
	fragment bool
}

func mkSeg(s seg) []byte {
	opts := 0
	if s.ts {
		opts += 12 // NOP NOP TS
	}
	if s.sack {
		opts += 12 // NOP NOP SACK(10)
	}
	tcpLen := 20 + opts + s.payload
	var p []byte
	var l4 []byte
	if s.v6 {
		p = make([]byte, 40+tcpLen)
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:6], uint16(tcpLen))
		p[6], p[7] = 6, 64
		p[8], p[24] = 0xfd, 0xfd
		p[23], p[39] = 2, 1
		l4 = p[40:]
	} else {
		p = make([]byte, 20+tcpLen)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		if s.fragment {
			binary.BigEndian.PutUint16(p[6:8], 0x2000)
		}
		p[8], p[9] = 64, 6
		copy(p[12:16], []byte{10, 8, 0, 2})
		copy(p[16:20], []byte{1, 1, 1, 1})
		l4 = p[20:]
	}
	binary.BigEndian.PutUint16(l4[0:2], s.sport)
	binary.BigEndian.PutUint16(l4[2:4], 443)
	binary.BigEndian.PutUint32(l4[8:12], s.ack)
	l4[12] = byte((20+opts)/4) << 4
	l4[13] = s.flags
	o := l4[20:]
	if s.ts {
		o[0], o[1], o[2], o[3] = 1, 1, 8, 10
		o = o[12:]
	}
	if s.sack {
		o[0], o[1], o[2], o[3] = 1, 1, 5, 10
	}
	return p
}
