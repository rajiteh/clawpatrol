package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func TestParsePeerStats(t *testing.T) {
	uapi := "last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=123456789\ntx_bytes=4096\nrx_bytes=8192\npersistent_keepalive_interval=25\n"
	got := parsePeerStats(uapi)
	if got == nil {
		t.Fatal("parsePeerStats returned nil")
	}
	wantHS := time.Unix(1700000000, 123456789)
	if !got.lastHandshake.Equal(wantHS) {
		t.Errorf("lastHandshake = %v, want %v", got.lastHandshake, wantHS)
	}
	if got.rxBytes != 8192 {
		t.Errorf("rxBytes = %d, want 8192", got.rxBytes)
	}
}

func TestParsePeerStatsNoHandshake(t *testing.T) {
	// last_handshake_time_sec=0 / _nsec=0 means "never" — don't interpret
	// that as a 1970 timestamp.
	got := parsePeerStats("last_handshake_time_sec=0\nlast_handshake_time_nsec=0\nrx_bytes=0\n")
	if got == nil {
		t.Fatal("parsePeerStats returned nil")
	}
	if !got.lastHandshake.IsZero() {
		t.Errorf("lastHandshake = %v, want zero", got.lastHandshake)
	}
}

// loggerWithLines returns a device.Logger that captures Errorf format
// strings, so tests can assert log behavior without touching os.Stdout.
func loggerWithLines() (*device.Logger, *[]string) {
	var lines []string
	l := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, _ ...any) {
			lines = append(lines, format)
		},
	}
	return l, &lines
}

// fakeClock advances synthetic time so the watchdog loop can be driven in
// microseconds.
type fakeClock struct {
	now atomic.Int64 // unix nanos
}

func (c *fakeClock) Now() time.Time  { return time.Unix(0, c.now.Load()) }
func (c *fakeClock) Set(t time.Time) { c.now.Store(t.UnixNano()) }

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("expected %s", what)
	}
}

func assertNoSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("unexpected %s", what)
	case <-time.After(80 * time.Millisecond):
	}
}

// TestWatchdogProbeEscalates drives the escalation ladder: rx is flat (the
// sidecar is the sole keepalive sender, so a quiet inbound is normal), so once
// rx has been quiet past probeAfter the watchdog probes; consecutive probe
// failures rekey, then reconnect.
func TestWatchdogProbeEscalates(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(3_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time)
	probeCalls := make(chan struct{}, 16)
	probe := func() error { probeCalls <- struct{}{}; return errors.New("no reply") }
	rekeyCalls := make(chan struct{}, 8)
	rekey := func() error { rekeyCalls <- struct{}{}; return nil }
	reconnectCalls := make(chan struct{}, 1)
	reconnect := func() {
		select {
		case reconnectCalls <- struct{}{}:
		default:
		}
	}
	rx := func() uint64 { return 1000 } // flat

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			rx: rx, probe: probe, rekey: rekey, reconnect: reconnect,
			log: log, tick: tick, now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()

	// Tick 1 seeds rx tracking — no probe (rx quiet only just observed).
	tick <- clk.Now()
	assertNoSignal(t, probeCalls, "probe on seed tick")

	// +25s: rx quiet past probeAfter → probe #1, fails (1) — no rekey yet.
	clk.Set(t0.Add(25 * time.Second))
	tick <- clk.Now()
	waitSignal(t, probeCalls, "probe #1")
	assertNoSignal(t, rekeyCalls, "rekey after a single failure")

	// +50s: probe #2, second consecutive failure → in-place rekey.
	clk.Set(t0.Add(50 * time.Second))
	tick <- clk.Now()
	waitSignal(t, probeCalls, "probe #2")
	waitSignal(t, rekeyCalls, "rekey at 2 consecutive failures")

	// +75s: probe #3, third failure → reconnect, loop returns.
	clk.Set(t0.Add(75 * time.Second))
	tick <- clk.Now()
	waitSignal(t, probeCalls, "probe #3")
	waitSignal(t, reconnectCalls, "reconnect at 3 consecutive failures")
	<-done
}

// TestWatchdogRxHealthyNoProbe confirms an advancing rx (real inbound traffic)
// is treated as liveness on its own — the watchdog never generates a probe.
func TestWatchdogRxHealthyNoProbe(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(6_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time)
	var rxv atomic.Uint64
	rxv.Store(1000)
	probeCalls := make(chan struct{}, 8)
	probe := func() error { probeCalls <- struct{}{}; return nil }

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			rx:        func() uint64 { return rxv.Load() },
			probe:     probe,
			rekey:     func() error { return nil },
			reconnect: func() {},
			log:       log, tick: tick, now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()

	tick <- clk.Now() // seed
	// Advance well past probeAfter each round, but with rx advancing → healthy.
	for i := 1; i <= 4; i++ {
		clk.Set(t0.Add(time.Duration(i) * 40 * time.Second))
		rxv.Add(32) // an inbound packet was received
		tick <- clk.Now()
	}
	assertNoSignal(t, probeCalls, "probe while rx is advancing")
	cancel()
	<-done
}

// TestWatchdogProbeSuccessIdle confirms that on a healthy-but-idle tunnel
// (rx flat, probe replies) the watchdog probes on cadence but never escalates.
func TestWatchdogProbeSuccessIdle(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(7_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time)
	probeCalls := make(chan struct{}, 16)
	probe := func() error { probeCalls <- struct{}{}; return nil } // reply
	rekeyCalls := make(chan struct{}, 8)
	rekey := func() error { rekeyCalls <- struct{}{}; return nil }
	reconnectCalls := make(chan struct{}, 1)
	reconnect := func() {
		select {
		case reconnectCalls <- struct{}{}:
		default:
		}
	}

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			rx: func() uint64 { return 1000 }, probe: probe, rekey: rekey, reconnect: reconnect,
			log: log, tick: tick, now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 2, reconnectAfterFails: 3,
		})
		close(done)
	}()

	tick <- clk.Now() // seed
	for i := 1; i <= 5; i++ {
		clk.Set(t0.Add(time.Duration(i) * 25 * time.Second))
		tick <- clk.Now()
		waitSignal(t, probeCalls, "idle liveness probe")
	}
	assertNoSignal(t, rekeyCalls, "rekey while probes succeed")
	assertNoSignal(t, reconnectCalls, "reconnect while probes succeed")
	cancel()
	<-done
}

// TestWatchdogInertWhenReapingDisabled confirms the loop returns immediately
// (never probes or escalates) when reaping is disabled server-side
// (reconnectAfterFails <= 0).
func TestWatchdogInertWhenReapingDisabled(t *testing.T) {
	clk := &fakeClock{}
	clk.Set(time.Unix(4_000_000, 0))
	probeCalls := make(chan struct{}, 4)
	log, _ := loggerWithLines()

	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(context.Background(), wgWatchdogConfig{
			rx:        func() uint64 { return 1000 },
			probe:     func() error { probeCalls <- struct{}{}; return errors.New("no reply") },
			rekey:     func() error { return nil },
			reconnect: func() {},
			log:       log, tick: make(chan time.Time), now: clk.Now,
			probeAfter: 25 * time.Second, probeInterval: 25 * time.Second,
			rekeyAfterFails: 0, reconnectAfterFails: 0,
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("inert watchdog should return immediately when reaping is disabled")
	}
	assertNoSignal(t, probeCalls, "probe with reaping disabled")
}

// TestWatchdogResetMisses checks the client-configured local-reset threshold
// resolved against the server reconnect horizon: used as-is below the horizon,
// disabled (0) at/above it or when non-positive.
func TestWatchdogResetMisses(t *testing.T) {
	for _, c := range []struct{ configured, reconnectAfter, want int }{
		{2, 3, 2},  // default: 2 failures → rekey, 3 → reconnect
		{2, 5, 2},  // large horizon still gets an early local rekey at 2
		{4, 10, 4}, // custom value honored below the horizon
		{2, 2, 0},  // == horizon → never fires; reconnect handles it
		{5, 3, 0},  // > horizon → clamped off
		{0, 3, 0},  // explicitly disabled
		{-1, 3, 0}, // guard non-positive
	} {
		if got := watchdogResetMisses(c.configured, c.reconnectAfter); got != c.want {
			t.Errorf("watchdogResetMisses(%d, %d) = %d, want %d", c.configured, c.reconnectAfter, got, c.want)
		}
	}
}
