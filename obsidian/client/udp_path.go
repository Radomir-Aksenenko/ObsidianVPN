package client

import (
	"sync/atomic"
	"time"

	"obsidian/obsidian"
)

// UDPPath decides, per packet, whether tunnel data goes over the direct UDP channel or over the
// TCP tunnel of the same session, and runs the probes that decide it.
//
// Real-time traffic (Discord, Telegram and WhatsApp calls, games) is what suffers when this
// decision is slow. Discord gives up on a voice server when its UDP IP discovery gets no answer
// within a few seconds and shows "RTC connecting" while it retries. The old logic sent data over
// UDP before anything had come back on it and only fell back to TCP after 8 s of silence (10 s
// counting the 2 s monitor tick), so on a network that drops UDP to the server every connect
// and every UDP failure was a blackout long enough to lose the call. On a network that lets the
// probes through but not the traffic itself, it went back to UDP every few seconds and lost it
// again.
//
// Now:
//   - A new session sends over TCP, which already works, and moves to UDP once an authenticated
//     UDP reply has come back. On a working network that takes one round trip.
//   - While on UDP, data that gets no authenticated answer for UDPProbeAfter triggers probes,
//     and after UDPDeadAfter the session moves to TCP.
//   - A UDP path that failed soon after it came back is held off for a growing time (10 s up to
//     5 min), so a path that only carries probes cannot make the session flap.
type UDPPath struct {
	active atomic.Bool
	// pending is the first UDP data send still waiting for any authenticated reply; 0 when none.
	pending atomic.Int64
	// failed is set by the data path when UDP sends keep failing.
	failed atomic.Bool
	// lastSend is the time of the last UDP data send.
	lastSend atomic.Int64

	// Owned by the goroutine that calls Step.
	start       time.Time
	startProbes int
	lastProbe   time.Time
	activatedAt time.Time
	holdUntil   time.Time
	downAt      time.Time
	hold        time.Duration
	schedule    obsidian.UDPProbeSchedule
	// probesSent counts probes sent while on UDP; lossSnaps samples it with the echo count.
	probesSent uint64
	lossSnaps  []lossSnap
}

type lossSnap struct {
	at             time.Time
	probes, echoes uint64
}

const (
	// UDPProbeAfter is how long UDP data may go unanswered before the path is probed.
	UDPProbeAfter = 1 * time.Second
	// UDPDeadAfter is how long UDP data may go unanswered before the session moves to TCP.
	// Probes are answered within one round trip, so this only fires on a path that is gone.
	UDPDeadAfter = 3 * time.Second
	// UDPPathTick is how often Step should run.
	UDPPathTick = 250 * time.Millisecond

	udpProbeGap = 500 * time.Millisecond
	// udpActivateWithin is how recent a UDP reply must be for the path to be taken (again).
	udpActivateWithin = 1500 * time.Millisecond
	udpHoldMin        = 10 * time.Second
	udpHoldMax        = 5 * time.Minute
	// udpStableAfter is how long UDP must have carried data for a later failure to count as new
	// rather than as part of a flapping path.
	udpStableAfter = 60 * time.Second

	// Loss check. A path that drops most datagrams without dropping all of them (a rate limit
	// on UDP to the server, a congested radio link) still answers some probes, so the silence
	// check never fires while calls break up. While data flows, two probes a second are sent;
	// when fewer than 40 % of the probes of the last udpLossWindow came back (more than about
	// 37 % loss each way, or 60 % one way), the session moves to TCP. With twenty probes a path
	// with 10 % loss each way trips it by chance about once in 100,000 windows.
	udpLossProbeGap  = 500 * time.Millisecond
	udpLossBusy      = 2 * time.Second
	udpLossSnapEvery = 2 * time.Second
	udpLossWindow    = 10 * time.Second
	udpLossMinProbes = 12
)

// udpStartProbes are the times after the start at which the first probes go out. A single
// datagram can be lost; the later ones also open a slow carrier NAT.
var udpStartProbes = [...]time.Duration{0, 300 * time.Millisecond, time.Second, 2 * time.Second}

// UDPPathChange describes a decision taken by Step.
type UDPPathChange int

const (
	UDPPathUnchanged UDPPathChange = iota
	UDPPathUp                      // data now goes over UDP
	UDPPathDown                    // data now goes over TCP
)

// NewUDPPath returns a path that sends over TCP until UDP has answered.
func NewUDPPath(now time.Time) *UDPPath {
	return &UDPPath{start: now}
}

// Active reports whether data should be sent over UDP.
func (p *UDPPath) Active() bool { return p.active.Load() }

// NoteSent records a successful UDP data send at nowNano. Safe from any goroutine.
func (p *UDPPath) NoteSent(nowNano int64) {
	p.lastSend.Store(nowNano)
	if p.pending.Load() == 0 {
		p.pending.CompareAndSwap(0, nowNano)
	}
}

// Fail moves data to TCP at once, for a data path whose UDP sends keep failing. Safe from any
// goroutine; Step applies the hold-off on its next run.
func (p *UDPPath) Fail() {
	if p.active.Swap(false) {
		p.failed.Store(true)
	}
}

// Step runs the path decision at now, given the arrival time of the last authenticated UDP
// datagram (0 if none) and the number of probe echoes received so far. It reports whether a
// probe should be sent and whether the path changed.
func (p *UDPPath) Step(now time.Time, authRecvNano int64, echoes uint64) (probe bool, change UDPPathChange) {
	if p.failed.Swap(false) {
		p.deactivate(now)
		change = UDPPathDown
	}
	if !p.active.Load() {
		if change == UDPPathUnchanged && authRecvNano > p.since() && !now.Before(p.holdUntil) &&
			now.Sub(time.Unix(0, authRecvNano)) <= udpActivateWithin {
			p.active.Store(true)
			p.pending.Store(0)
			p.activatedAt = now
			p.schedule = obsidian.UDPProbeSchedule{}
			p.lossSnaps = p.lossSnaps[:0]
			return false, UDPPathUp
		}
		if p.startProbes < len(udpStartProbes) {
			if now.Sub(p.start) >= udpStartProbes[p.startProbes] {
				p.startProbes++
				return p.probe(now), change
			}
			return false, change
		}
		if !now.Before(p.holdUntil) && p.schedule.Due(now, false, authRecvNano) {
			return p.probe(now), change
		}
		return false, change
	}

	// Any authenticated datagram after the pending send proves the path is alive, even one that
	// Recv skipped (an empty keepalive echo).
	if pending := p.pending.Load(); pending != 0 && authRecvNano >= pending {
		p.pending.CompareAndSwap(pending, 0)
	}
	var silent time.Duration
	if pending := p.pending.Load(); pending != 0 {
		silent = now.Sub(time.Unix(0, pending))
	}
	switch DecideUDPHealth(silent, authRecvNano > p.start.UnixNano(), true) {
	case UDPHealthFailover, UDPHealthReconnect:
		p.active.Store(false)
		p.deactivate(now)
		return false, UDPPathDown
	case UDPHealthProbe:
		if now.Sub(p.lastProbe) >= udpProbeGap {
			return p.probe(now), UDPPathUnchanged
		}
		return false, UDPPathUnchanged
	}
	if p.lossy(now, echoes) {
		p.active.Store(false)
		p.deactivate(now)
		return false, UDPPathDown
	}
	if now.Sub(time.Unix(0, p.lastSend.Load())) < udpLossBusy && now.Sub(p.lastProbe) >= udpLossProbeGap {
		return p.probe(now), UDPPathUnchanged
	}
	if p.schedule.Due(now, true, authRecvNano) {
		// Keepalive so carrier CGNAT pinholes stay open during quiet periods.
		return p.probe(now), UDPPathUnchanged
	}
	return false, UDPPathUnchanged
}

// since is the time after which a UDP reply counts as proof that the path works now.
func (p *UDPPath) since() int64 {
	if p.downAt.After(p.start) {
		return p.downAt.UnixNano()
	}
	return p.start.UnixNano()
}

func (p *UDPPath) probe(now time.Time) bool {
	p.lastProbe = now
	if p.active.Load() {
		p.probesSent++
	}
	return true
}

// lossy samples probes and echoes and reports whether fewer than 40 % of the probes sent over
// the last udpLossWindow were echoed.
func (p *UDPPath) lossy(now time.Time, echoes uint64) bool {
	if n := len(p.lossSnaps); n > 0 && now.Sub(p.lossSnaps[n-1].at) < udpLossSnapEvery {
		return false
	}
	// A probe sent in the last round trip cannot have been answered yet.
	settled := p.probesSent
	if settled > 0 && now.Sub(p.lastProbe) < udpProbeGap {
		settled--
	}
	p.lossSnaps = append(p.lossSnaps, lossSnap{at: now, probes: settled, echoes: echoes})
	first := 0
	for first < len(p.lossSnaps)-1 && now.Sub(p.lossSnaps[first+1].at) >= udpLossWindow {
		first++
	}
	p.lossSnaps = p.lossSnaps[first:]
	old := p.lossSnaps[0]
	if now.Sub(old.at) < udpLossWindow {
		return false
	}
	sent := settled - old.probes
	got := min(echoes-old.echoes, sent)
	return sent >= udpLossMinProbes && 5*got < 2*sent
}

// deactivate starts the hold-off after UDP stopped working. A path that had carried data for a
// while gets retried as soon as it answers; one that failed again soon after coming back waits
// twice as long as last time.
func (p *UDPPath) deactivate(now time.Time) {
	p.pending.Store(0)
	p.downAt = now
	if !p.activatedAt.IsZero() && now.Sub(p.activatedAt) >= udpStableAfter {
		p.hold = 0
	} else {
		p.hold = min(max(2*p.hold, udpHoldMin), udpHoldMax)
	}
	p.holdUntil = now.Add(p.hold)
	p.schedule = obsidian.UDPProbeSchedule{}
}

// HoldOff returns how long the path is held on TCP after the last failure. For tests and logs.
func (p *UDPPath) HoldOff() time.Duration { return p.hold }
