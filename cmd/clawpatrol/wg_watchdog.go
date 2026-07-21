package main

// Liveness self-heal for an enrolled bridge peer's WireGuard tunnel.
//
// Enrolled peers run with symmetric persistent-keepalive: the gateway
// keepalives back (see AddPeer), so the peer's rx_bytes advances every
// keepalive interval on a healthy tunnel — with no application traffic and
// no app-level heartbeat. When rx_bytes stalls, the far side has stopped
// responding: the gateway reaped or is partitioned from the peer, or the
// local wireguard-go handshake state machine wedged. Either way the tunnel
// is dead and won't recover on its own.
//
// The watchdog samples rx_bytes and escalates in two steps, sized from the
// gateway-pushed keepalive cadence and timeout multiplier:
//
//   - at rxResetAfter (one keepalive before the reap horizon): rebuild the
//     peer in place with the original IpcSet config. This is cheap and
//     clears a transient local wedge without dropping the enrollment.
//   - at rxExitAfter (the reap horizon + jitter): the enrollment is gone or
//     unrecoverable in place, so exit() — the kubelet restarts the native
//     sidecar, which re-enrolls with a fresh key (a fresh keypair also
//     sidesteps a wedged handshake state machine).
//
// The loop is inert (thresholds zero) for clients that don't run symmetric
// keepalive, so a flat rx is never mistaken for a dead tunnel there.

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const (
	// wgWatchdogPoll is how often the watchdog samples the peer's
	// rx_bytes. Several samples per keepalive interval keeps detection
	// prompt while staying cheap.
	wgWatchdogPoll = 5 * time.Second
	// wgWatchdogResetCooldown holds off back-to-back in-place rebuilds so a
	// reset has time to take effect before the next one fires.
	wgWatchdogResetCooldown = time.Minute
	// wgWatchdogResetMisses is the default for the client-configurable
	// local-reset threshold: how many missed keepalives trigger the cheap
	// in-place rebuild before the (server-dictated) full restart. Independent
	// of the timeout multiplier, so even a tolerant reap horizon still gets
	// an early recovery attempt.
	wgWatchdogResetMisses = 2
)

// wgPeerStats is the per-peer subset of IpcGet output the watchdog reads.
// lastHandshake is only used to gate escalation on the first handshake
// completing (a tunnel that never came up is a setup problem, not a reap).
type wgPeerStats struct {
	lastHandshake time.Time
	rxBytes       uint64
}

// wgWatchdogConfig captures the runWGWatchdogLoop dependencies so the loop
// is testable without a real wireguard-go device.
type wgWatchdogConfig struct {
	stats         func() *wgPeerStats
	reset         func() error
	exit          func()
	log           *device.Logger
	tick          <-chan time.Time
	resetCooldown time.Duration
	// rxResetAfter / rxExitAfter are the rx-quiet thresholds for the local
	// rebuild and the hard exit. Both zero leaves the loop inert.
	rxResetAfter time.Duration
	rxExitAfter  time.Duration
	now          func() time.Time
}

// watchdogResetMisses resolves the client-configured local-reset threshold
// (missed keepalives) against the server's restart horizon (mult), returning
// the missed-keepalive count that should trigger the in-place rebuild, or 0
// to disable it. 0 disables it explicitly; a value at or above mult also
// disables it (the reset would never beat the full restart at the reap
// horizon, so it is not scheduled). Otherwise the configured value is used.
func watchdogResetMisses(configured, mult int) int {
	if configured <= 0 || configured >= mult {
		return 0
	}
	return configured
}

func runWGWatchdogLoop(ctx context.Context, c wgWatchdogConfig) {
	var (
		seenHandshake bool
		rxTracking    bool
		lastRx        uint64
		lastRxAt      time.Time
		lastResetAt   time.Time
	)
	logf := func(format string, args ...any) {
		if c.log != nil && c.log.Errorf != nil {
			c.log.Errorf(format, args...)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.tick:
		}

		s := c.stats()
		if s == nil {
			continue
		}
		if !s.lastHandshake.IsZero() {
			seenHandshake = true
		}
		// Don't escalate before the first handshake: a tunnel that never
		// came up is a config/network problem that a rebuild or restart
		// won't fix any faster, and would only crash-loop.
		if !seenHandshake {
			continue
		}

		switch {
		case !rxTracking:
			rxTracking, lastRx, lastRxAt = true, s.rxBytes, c.now()
		case s.rxBytes > lastRx:
			lastRx, lastRxAt = s.rxBytes, c.now()
		default:
			quiet := c.now().Sub(lastRxAt)
			if c.rxExitAfter > 0 && quiet > c.rxExitAfter {
				logf("watchdog: no WG rx for %s (> %s) — peer reaped or partitioned; exiting to re-enroll",
					quiet.Round(time.Second), c.rxExitAfter)
				if c.exit != nil {
					c.exit()
				}
				return
			}
			if c.rxResetAfter > 0 && quiet > c.rxResetAfter &&
				(lastResetAt.IsZero() || c.now().Sub(lastResetAt) >= c.resetCooldown) {
				logf("watchdog: no WG rx for %s (> %s) — rebuilding peer",
					quiet.Round(time.Second), c.rxResetAfter)
				if err := c.reset(); err != nil {
					logf("watchdog: peer reset failed: %v", err)
				} else {
					lastResetAt = c.now()
				}
			}
		}
	}
}

func parsePeerStats(uapi string) *wgPeerStats {
	s := &wgPeerStats{}
	var secs, nsec int64
	sc := bufio.NewScanner(strings.NewReader(uapi))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec":
			secs, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nsec, _ = strconv.ParseInt(v, 10, 64)
		case "rx_bytes":
			x, _ := strconv.ParseUint(v, 10, 64)
			s.rxBytes = x
		}
	}
	if secs != 0 || nsec != 0 {
		s.lastHandshake = time.Unix(secs, nsec)
	}
	return s
}
