package obsidian

import (
	"encoding/binary"
	"testing"
)

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

func acks(pkts [][]byte) []uint32 {
	var out []uint32
	for _, p := range pkts {
		ihl := 40
		if p[0]>>4 == 4 {
			ihl = int(p[0]&0x0f) * 4
		}
		out = append(out, binary.BigEndian.Uint32(p[ihl+8:ihl+12]))
	}
	return out
}

func TestThinACKs(t *testing.T) {
	const ack = 0x10
	cases := []struct {
		name string
		in   []seg
		want []uint32
	}{
		{"superseded acks of one flow keep only the newest",
			[]seg{{sport: 1, ack: 100, flags: ack, ts: true}, {sport: 1, ack: 200, flags: ack, ts: true}, {sport: 1, ack: 300, flags: ack, ts: true}},
			[]uint32{300}},
		{"duplicate acks are kept",
			[]seg{{sport: 1, ack: 100, flags: ack}, {sport: 1, ack: 100, flags: ack}, {sport: 1, ack: 100, flags: ack}},
			[]uint32{100, 100, 100}},
		{"other flows and order are kept",
			[]seg{{sport: 1, ack: 100, flags: ack}, {sport: 2, ack: 50, flags: ack}, {sport: 1, ack: 200, flags: ack}, {sport: 2, ack: 60, flags: ack}},
			[]uint32{200, 60}},
		{"sack acks are kept and keep later ones",
			[]seg{{sport: 1, ack: 100, flags: ack, sack: true}, {sport: 1, ack: 200, flags: ack, sack: true}},
			[]uint32{100, 200}},
		{"segments with data are kept",
			[]seg{{sport: 1, ack: 100, flags: ack, payload: 10}, {sport: 1, ack: 200, flags: ack}},
			[]uint32{100, 200}},
		{"fin syn rst push and ece are kept",
			[]seg{{sport: 1, ack: 100, flags: ack | 0x01}, {sport: 1, ack: 110, flags: ack | 0x08}, {sport: 1, ack: 120, flags: ack | 0x40}, {sport: 1, ack: 130, flags: 0x04}, {sport: 1, ack: 140, flags: ack}},
			[]uint32{100, 110, 120, 130, 140}},
		{"an older ack after a newer one is not dropped twice",
			[]seg{{sport: 1, ack: 300, flags: ack}, {sport: 1, ack: 200, flags: ack}},
			[]uint32{300, 200}},
		{"wraparound counts as newer",
			[]seg{{sport: 1, ack: 0xfffffff0, flags: ack}, {sport: 1, ack: 0x10, flags: ack}},
			[]uint32{0x10}},
		{"fragments are kept",
			[]seg{{sport: 1, ack: 100, flags: ack, fragment: true}, {sport: 1, ack: 200, flags: ack}},
			[]uint32{100, 200}},
		{"ipv6 acks thin too",
			[]seg{{v6: true, sport: 1, ack: 100, flags: ack}, {v6: true, sport: 1, ack: 200, flags: ack}},
			[]uint32{200}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var in [][]byte
			for _, s := range tc.in {
				in = append(in, mkSeg(s))
			}
			got := acks(ThinACKs(in))
			if len(got) != len(tc.want) {
				t.Fatalf("got acks %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got acks %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func BenchmarkThinACKs(b *testing.B) {
	var src [][]byte
	for i := 0; i < 32; i++ {
		src = append(src, mkSeg(seg{sport: uint16(i % 3), ack: uint32(i * 1000), flags: 0x10, ts: true}))
	}
	pkts := make([][]byte, len(src))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		copy(pkts, src)
		_ = ThinACKs(pkts[:len(src)])
	}
}
