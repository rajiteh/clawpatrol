package main

// Liveness self-heal for an enrolled bridge peer's WireGuard tunnel.
//
// The sidecar is the sole (authoritative) keepalive sender — the gateway does
// not keepalive back (see registerEnrolledPeer) — so the sidecar's own
// rx_bytes is normally quiet on an idle tunnel. The watchdog therefore uses
// rx_bytes only as a cheap positive signal: while it advances, inbound works
// and nothing is done. When it goes quiet, the watchdog actively probes the
// gateway's tunnel address with an ICMP echo to disambiguate "healthy but
// idle" from "actually broken" — a round-trip reply proves both directions.
//
// On sustained probe failure it escalates:
//
//   - at rekeyAfterFails consecutive failures: rebuild the peer in place
//     (IpcSet). Cheap; clears a transient local wedge.
//   - at reconnectAfterFails consecutive failures: trigger a full in-process
//     teardown + re-enroll (reconnect), then return so a fresh watchdog runs
//     with the new session.
//
// It never exits the process: a native-sidecar restart lands in the same pod
// sandbox and resets nothing a device rebuild doesn't, so recovery stays
// in-process. The loop is inert (reconnectAfterFails <= 0) when the gateway
// has reaping disabled, so a quiet tunnel is never acted on there.

import (
	"bufio"
	"context"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const (
	// wgWatchdogPoll is how often the loop samples rx_bytes. Small so the
	// watchdog reacts promptly when real inbound traffic resumes.
	wgWatchdogPoll = 5 * time.Second
	// wgWatchdogResetMisses is the default for --local-reset-missed: how many
	// consecutive failed probes trigger the cheap in-place rekey before the
	// full reconnect. Clamped below the reconnect threshold.
	wgWatchdogResetMisses = 2
)

// wgPeerStats is the per-peer subset of IpcGet output the watchdog reads.
type wgPeerStats struct {
	lastHandshake time.Time
	rxBytes       uint64
}

// wgWatchdogConfig captures the runWGWatchdogLoop dependencies so the loop is
// testable without a real wireguard-go device or a real network.
type wgWatchdogConfig struct {
	// rx returns the peer's current WireGuard rx_bytes (0 if unavailable).
	rx func() uint64
	// probe sends one liveness probe (ICMP echo to the gateway tunnel IP) and
	// returns nil on a reply, an error on failure/timeout.
	probe func() error
	// rekey rebuilds the peer in place (IpcSet) — the cheap first escalation.
	rekey func() error
	// reconnect triggers a full in-process teardown + re-enroll. After it is
	// called the loop returns; a fresh watchdog starts with the new session.
	reconnect func()
	log       *device.Logger
	tick      <-chan time.Time
	now       func() time.Time
	// probeAfter is how long rx must be quiet before the first probe;
	// probeInterval rate-limits probes once quiet. Both are the keepalive
	// interval in practice.
	probeAfter    time.Duration
	probeInterval time.Duration
	// rekeyAfterFails / reconnectAfterFails are consecutive-probe-failure
	// counts. rekeyAfterFails == 0 disables the in-place rekey stage;
	// reconnectAfterFails <= 0 leaves the whole loop inert (reaping disabled).
	rekeyAfterFails     int
	reconnectAfterFails int
}

// watchdogResetMisses resolves the configured local-reset threshold against
// the reconnect horizon: 0 (or a value >= the horizon) disables the in-place
// rekey stage, otherwise the configured value is used.
func watchdogResetMisses(configured, reconnectAfter int) int {
	if configured <= 0 || configured >= reconnectAfter {
		return 0
	}
	return configured
}

func runWGWatchdogLoop(ctx context.Context, c wgWatchdogConfig) {
	logf := func(format string, args ...any) {
		if c.log != nil && c.log.Errorf != nil {
			c.log.Errorf(format, args...)
		}
	}
	// Inert when reaping is disabled server-side: nothing to escalate to.
	if c.reconnectAfterFails <= 0 {
		return
	}
	var (
		tracking  bool
		lastRx    uint64
		lastLive  time.Time
		lastProbe time.Time
		fails     int
		rekeyed   bool
		rekeys    int
	)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.tick:
		}
		now := c.now()
		rx := c.rx()
		if !tracking {
			tracking, lastRx, lastLive = true, rx, now
			continue
		}
		if rx > lastRx {
			// Positive inbound signal — the tunnel is healthy, no probe needed.
			if fails > 0 || rekeyed {
				logf("watchdog: WG rx resumed — tunnel healthy again")
			}
			lastRx, lastLive, fails, rekeyed = rx, now, 0, false
			continue
		}
		// rx is quiet. Act only once it has been quiet long enough, and
		// rate-limit the probe to the probe interval.
		if now.Sub(lastLive) < c.probeAfter {
			continue
		}
		if !lastProbe.IsZero() && now.Sub(lastProbe) < c.probeInterval {
			continue
		}
		lastProbe = now
		if err := c.probe(); err == nil {
			// Healthy but idle. The reply also advances rx (handled next tick),
			// but count the success as liveness now.
			if fails > 0 || rekeyed {
				logf("watchdog: gateway probe recovered — tunnel healthy again")
			}
			lastRx, lastLive, fails, rekeyed = c.rx(), now, 0, false
			continue
		} else {
			fails++
			logf("watchdog: gateway liveness probe failed (%d/%d): %v", fails, c.reconnectAfterFails, err)
		}
		if fails >= c.reconnectAfterFails {
			logf("watchdog: %d consecutive probe failures — tearing down and reconnecting in-process", fails)
			if c.reconnect != nil {
				c.reconnect()
			}
			return
		}
		if c.rekeyAfterFails > 0 && fails >= c.rekeyAfterFails && !rekeyed {
			rekeys++
			logf("watchdog: %d consecutive probe failures — rebuilding peer in place (rekey #%d)", fails, rekeys)
			if err := c.rekey(); err != nil {
				logf("watchdog: peer rekey failed: %v", err)
			} else {
				rekeyed = true
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
