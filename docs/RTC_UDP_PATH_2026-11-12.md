# Calls through the tunnel: UDP path choice (2026-11-12)

Reported: Discord stays on "RTC connecting" and calls are poor. Discord voice is plain UDP
(IP discovery, then RTP); it has no TCP fallback of its own, so it depends on how fast the tunnel
moves inner UDP when the outer UDP data channel does not work well.

## What was wrong

Measured with `tools/rtclab` (real client engine on a TUN, real server, a voice server behind the
server's NAT, REALITY + direct UDP as the app deploys it). With a clean network everything worked:
IP discovery, datagrams up to 4000 bytes both ways, 0 % loss. The failures were all in the choice
between the direct UDP channel and the TCP tunnel:

| Scenario (outer UDP to the server) | Before | After |
|---|---|---|
| Uplink UDP silently dropped from the start | 8.5 s of total silence after connect, 42 % loss in 20 s | 0 s, 0 % |
| Downlink UDP silently dropped from the start | 10.5 s of silence | 0 s, 0 % |
| Downlink UDP dropped 10 s into a call, for 10 s | 10.0 s of silence: no failover at all within the outage | one 3.9 s gap |
| UDP rate limited to 20 pps (probes pass, a call does not) | 58.7 % loss for the whole call, never left UDP | detected in 10–12 s, retries back off 10 s, 20 s, 40 s… up to 5 min; 27.5 % loss in the first minute, less later |

Causes:

1. A new session sent data over UDP before anything had come back on it and only fell back after
   8 s of silence, checked every 2 s. Joining a voice channel right after connecting, or any
   reconnect on a network that drops UDP to the server, lost Discord's IP discovery.
2. The server kept sending downlink over UDP for 2 s after the client's data moved to TCP.
3. A path that drops most but not all datagrams kept answering some probes, so the silence check
   never fired.
4. After a failover, any answered probe put the session back on UDP, so a path that carries
   probes but not traffic could make it flap every few seconds.

## What changed

- `obsidian/client/udp_path.go` (`UDPPath`), used by the mobile engine and the desktop client:
  - a new session sends over TCP, which is already up, and moves to UDP once an authenticated UDP
    reply arrives (one round trip on a working network);
  - unanswered UDP data is probed after 1 s and moved to TCP after 3 s (decided every 250 ms);
  - while data flows, two empty probes a second measure round-trip loss; fewer than 40 % echoed
    over 10 s (about 37 % loss each way, or 60 % one way) moves the session to TCP. With 10 % loss
    each way this trips by chance about once in 100,000 windows;
  - a path that fails soon after it came back is held on TCP for 10 s, doubling up to 5 min; a
    path that carried data for a minute is retried as soon as it answers.
- `UDPChannel.EchoCount` counts the server's echoes of empty probes.
- Server: downlink follows the client to TCP after 500 ms instead of 2 s
  (`udpDownlinkGrace`). Old clients and old servers keep working with either side updated.

## Limits

- Loss is measured round trip; a path that loses less than about 37 % each way stays on UDP.
- The lab had no netem, so the numbers are for a sub-millisecond link. Round-trip time only
  matters for the 1.5 s activation window and the 3 s silence limit, both far above mobile
  RTTs.
- Nothing here changes what happens on a network where both UDP and the TCP tunnel are bad.
