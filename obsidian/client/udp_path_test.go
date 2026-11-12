package client

import (
	"math/rand/v2"
	"testing"
	"time"
)

// pathSim drives a UDPPath with a fake clock and a fake UDP channel.
type pathSim struct {
	t       *testing.T
	p       *UDPPath
	now     time.Time
	auth    int64 // last authenticated arrival
	probes  int
	answers bool    // the path answers probes and data
	loss    float64 // chance that each datagram is lost, each way
	rng     *rand.Rand
	rtt     time.Duration // reply delay
	queued  []reply       // replies in flight
	echoes  uint64
	ups     int
	downs   int
}

type reply struct {
	at   time.Time
	echo bool
}

func newPathSim(t *testing.T, answers bool) *pathSim {
	start := time.Unix(1_800_000_000, 0)
	return &pathSim{t: t, p: NewUDPPath(start), now: start, answers: answers, rtt: 40 * time.Millisecond,
		rng: rand.New(rand.NewPCG(1, 2))}
}

func (s *pathSim) send(echo bool) {
	if !s.answers {
		return
	}
	if s.loss > 0 && (s.rng.Float64() < s.loss || s.rng.Float64() < s.loss) {
		return
	}
	s.queued = append(s.queued, reply{s.now.Add(s.rtt), echo})
}

// advance moves the clock by d in UDPPathTick steps, sending data at pps over UDP while the
// path is active (each data packet gets an answer when the path answers).
func (s *pathSim) advance(d time.Duration, pps int) {
	end := s.now.Add(d)
	var nextData time.Time
	if pps > 0 {
		nextData = s.now
	}
	for s.now.Before(end) {
		step := 10 * time.Millisecond
		s.now = s.now.Add(step)
		kept := s.queued[:0]
		for _, r := range s.queued {
			if !r.at.After(s.now) {
				s.auth = r.at.UnixNano()
				if r.echo {
					s.echoes++
				}
			} else {
				kept = append(kept, r)
			}
		}
		s.queued = kept
		if pps > 0 && !s.now.Before(nextData) {
			nextData = nextData.Add(time.Second / time.Duration(pps))
			if s.p.Active() {
				s.p.NoteSent(s.now.UnixNano())
				s.send(false)
			}
		}
		if s.now.UnixNano()%int64(UDPPathTick) < int64(step) {
			probe, change := s.p.Step(s.now, s.auth, s.echoes)
			if probe {
				s.probes++
				s.send(true)
			}
			switch change {
			case UDPPathUp:
				s.ups++
			case UDPPathDown:
				s.downs++
			}
		}
	}
}

func TestUDPPathStartsOnTCPAndMovesToUDPAfterAnswer(t *testing.T) {
	s := newPathSim(t, true)
	if s.p.Active() {
		t.Fatal("a new path must send over TCP until UDP answers")
	}
	s.advance(600*time.Millisecond, 50)
	if !s.p.Active() || s.ups != 1 {
		t.Fatalf("path did not move to UDP after an answer: active=%v ups=%d probes=%d", s.p.Active(), s.ups, s.probes)
	}
	s.advance(2*time.Minute, 50)
	if !s.p.Active() || s.downs != 0 {
		t.Fatalf("a working path went down: active=%v downs=%d", s.p.Active(), s.downs)
	}
}

func TestUDPPathNeverAnsweringStaysOnTCP(t *testing.T) {
	s := newPathSim(t, false)
	s.advance(time.Minute, 50)
	if s.p.Active() || s.ups != 0 || s.downs != 0 {
		t.Fatalf("a dead path must stay on TCP without flapping: active=%v ups=%d downs=%d", s.p.Active(), s.ups, s.downs)
	}
	// Start probes plus recovery probes about every 7 s.
	if s.probes < len(udpStartProbes)+5 || s.probes > len(udpStartProbes)+12 {
		t.Fatalf("probes = %d over a minute", s.probes)
	}
}

func TestUDPPathFailsOverWithinDeadline(t *testing.T) {
	s := newPathSim(t, true)
	s.advance(time.Second, 50)
	if !s.p.Active() {
		t.Fatal("path not up")
	}
	s.answers = false
	s.queued = nil
	died := s.now
	for s.p.Active() && s.now.Sub(died) < 10*time.Second {
		s.advance(10*time.Millisecond, 50)
	}
	if s.p.Active() {
		t.Fatal("path still active 10 s after it stopped answering")
	}
	if took := s.now.Sub(died); took > UDPDeadAfter+UDPPathTick+50*time.Millisecond {
		t.Fatalf("failover took %v, want at most about %v", took, UDPDeadAfter)
	}
}

func TestUDPPathOneWayTrafficIsNotMistakenForDead(t *testing.T) {
	// Data that gets no answers of its own (one speaker in a call) must stay on UDP as long as
	// the probes are answered.
	s := newPathSim(t, true)
	s.advance(time.Second, 0)
	if !s.p.Active() {
		t.Fatal("path not up")
	}
	end := s.now.Add(30 * time.Second)
	for s.now.Before(end) {
		if s.p.Active() {
			s.p.NoteSent(s.now.UnixNano()) // no reply queued: data is one-way
		}
		s.advance(20*time.Millisecond, 0)
	}
	if !s.p.Active() || s.downs != 0 {
		t.Fatalf("one-way UDP data was taken for a dead path: downs=%d", s.downs)
	}
}

func TestUDPPathFlappingBacksOff(t *testing.T) {
	// The path answers probes but loses data: each return to UDP fails again.
	s := newPathSim(t, true)
	var holds []time.Duration
	for i := 0; i < 5; i++ {
		s.answers = true
		for !s.p.Active() {
			s.advance(10*time.Millisecond, 0)
		}
		s.answers = false
		s.queued = nil
		for s.p.Active() {
			s.advance(10*time.Millisecond, 50)
		}
		holds = append(holds, s.p.HoldOff())
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second}
	for i := range want {
		if holds[i] != want[i] {
			t.Fatalf("hold-offs = %v, want %v", holds, want)
		}
	}
	// The hold-off is respected: the path answers again but stays on TCP until it ends.
	s.answers = true
	s.advance(150*time.Second, 0)
	if s.p.Active() {
		t.Fatal("path came back before its hold-off ended")
	}
	s.advance(20*time.Second, 0)
	if !s.p.Active() {
		t.Fatal("path did not come back after its hold-off")
	}
}

func TestUDPPathStableFailureRetriesAtOnce(t *testing.T) {
	s := newPathSim(t, true)
	s.advance(2*udpStableAfter, 50)
	s.answers = false
	s.queued = nil
	for s.p.Active() {
		s.advance(10*time.Millisecond, 50)
	}
	if s.p.HoldOff() != 0 {
		t.Fatalf("hold-off after a long working stretch = %v, want 0", s.p.HoldOff())
	}
	s.answers = true
	s.advance(2*time.Second, 50)
	if !s.p.Active() {
		t.Fatal("a path that answers again after a long working stretch was not retried")
	}
}

func TestUDPPathFailFromDataPath(t *testing.T) {
	s := newPathSim(t, true)
	s.advance(time.Second, 50)
	s.p.Fail()
	if s.p.Active() {
		t.Fatal("Fail must stop UDP at once")
	}
	s.advance(UDPPathTick, 0)
	if s.downs != 1 || s.p.HoldOff() != udpHoldMin {
		t.Fatalf("downs=%d hold=%v", s.downs, s.p.HoldOff())
	}
}

func TestUDPPathHeavyLossMovesToTCP(t *testing.T) {
	s := newPathSim(t, true)
	s.advance(time.Second, 50)
	if !s.p.Active() {
		t.Fatal("path not up")
	}
	s.loss = 0.5 // 75 % of round trips lost: some answers, calls unusable
	lossy := s.now
	for s.p.Active() && s.now.Sub(lossy) < 30*time.Second {
		s.advance(10*time.Millisecond, 50)
	}
	if s.p.Active() {
		t.Fatal("path still on UDP after 30 s of heavy loss")
	}
	if took := s.now.Sub(lossy); took > udpLossWindow+udpLossSnapEvery+time.Second {
		t.Fatalf("loss failover took %v", took)
	}
}

func TestUDPPathModerateLossStaysOnUDP(t *testing.T) {
	for seed := uint64(1); seed <= 40; seed++ {
		s := newPathSim(t, true)
		s.rng = rand.New(rand.NewPCG(seed, 7))
		s.advance(time.Second, 50)
		s.loss = 0.10
		s.advance(3*time.Minute, 50)
		if !s.p.Active() || s.downs != 0 {
			t.Fatalf("seed %d: 10 %% loss moved the session off UDP (downs=%d)", seed, s.downs)
		}
	}
}

func TestUDPPathLossProbesOnlyWhileBusy(t *testing.T) {
	s := newPathSim(t, true)
	s.advance(time.Second, 50)
	before := s.probes
	s.advance(time.Minute, 0) // idle: keepalives only
	if idle := s.probes - before; idle > 8 {
		t.Fatalf("%d probes in an idle minute", idle)
	}
	before = s.probes
	s.advance(time.Minute, 50)
	if busy := s.probes - before; busy < 100 || busy > 130 {
		t.Fatalf("%d probes in a busy minute, want about two a second", busy)
	}
}
