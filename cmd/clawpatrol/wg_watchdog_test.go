package main

import (
	"context"
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

// TestWatchdogRxLivenessEscalates drives the enrolled-peer path: a flat
// rx_bytes (gateway stopped responding) first triggers a local reset at
// rxResetAfter, then a hard exit at rxExitAfter when the reset didn't help.
func TestWatchdogRxLivenessEscalates(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(3_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time, 4)
	// Handshake completed at t0 (unblocks the first-handshake gate); rx flat.
	stats := func() *wgPeerStats {
		return &wgPeerStats{lastHandshake: t0, rxBytes: 1000}
	}
	resetCalls := make(chan struct{}, 8)
	reset := func() error { resetCalls <- struct{}{}; return nil }
	exitCalls := make(chan struct{}, 1)
	exit := func() {
		select {
		case exitCalls <- struct{}{}:
		default:
		}
	}

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			stats: stats, reset: reset, exit: exit, log: log, tick: tick,
			resetCooldown: time.Minute, rxResetAfter: 50 * time.Second,
			rxExitAfter: 75 * time.Second, now: clk.Now,
		})
		close(done)
	}()

	// Tick 1 seeds rx tracking (first sight) — no action.
	tick <- clk.Now()
	select {
	case <-resetCalls:
		t.Fatal("reset on first rx sample")
	case <-exitCalls:
		t.Fatal("exit on first rx sample")
	case <-time.After(50 * time.Millisecond):
	}

	// Past rxResetAfter (60s > 50s), rx still flat → local reset.
	clk.Set(t0.Add(60 * time.Second))
	tick <- clk.Now()
	select {
	case <-resetCalls:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not reset at rxResetAfter")
	}

	// Past rxExitAfter (80s > 75s), rx still flat → hard exit.
	clk.Set(t0.Add(80 * time.Second))
	tick <- clk.Now()
	select {
	case <-exitCalls:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not exit at rxExitAfter")
	}
	<-done // loop returns after exit()
}

// TestWatchdogWaitsForFirstHandshake confirms the loop never escalates
// before a handshake has completed, even with rx flat and thresholds set —
// a tunnel that never came up is a setup problem, not a reap.
func TestWatchdogWaitsForFirstHandshake(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(5_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time, 4)
	stats := func() *wgPeerStats {
		return &wgPeerStats{lastHandshake: time.Time{}, rxBytes: 0} // no handshake yet
	}
	resetCalls := make(chan struct{}, 8)
	reset := func() error { resetCalls <- struct{}{}; return nil }
	exited := false
	exit := func() { exited = true }

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			stats: stats, reset: reset, exit: exit, log: log, tick: tick,
			resetCooldown: time.Minute, rxResetAfter: 50 * time.Second,
			rxExitAfter: 75 * time.Second, now: clk.Now,
		})
		close(done)
	}()

	tick <- clk.Now()
	clk.Set(t0.Add(10 * time.Minute))
	tick <- clk.Now()
	select {
	case <-resetCalls:
		t.Fatal("reset before any handshake completed")
	case <-time.After(80 * time.Millisecond):
	}
	if exited {
		t.Fatal("exit before any handshake completed")
	}
	cancel()
	<-done
}

// TestWatchdogRxLivenessDisabled confirms a flat rx never resets or exits
// when the thresholds are zero (a client without symmetric keepalive).
func TestWatchdogRxLivenessDisabled(t *testing.T) {
	clk := &fakeClock{}
	t0 := time.Unix(4_000_000, 0)
	clk.Set(t0)

	tick := make(chan time.Time, 4)
	// Fresh handshake so the first-handshake gate passes; rx flat.
	stats := func() *wgPeerStats {
		return &wgPeerStats{lastHandshake: clk.Now(), rxBytes: 1000}
	}
	resetCalls := make(chan struct{}, 8)
	reset := func() error { resetCalls <- struct{}{}; return nil }
	exited := false
	exit := func() { exited = true }

	log, _ := loggerWithLines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runWGWatchdogLoop(ctx, wgWatchdogConfig{
			stats: stats, reset: reset, exit: exit, log: log, tick: tick,
			resetCooldown: time.Minute, now: clk.Now, // rxResetAfter/rxExitAfter zero → inert
		})
		close(done)
	}()

	tick <- clk.Now()
	clk.Set(t0.Add(10 * time.Minute))
	tick <- clk.Now()
	select {
	case <-resetCalls:
		t.Fatal("reset fired with rx escalation disabled")
	case <-time.After(80 * time.Millisecond):
	}
	if exited {
		t.Fatal("exit fired with rx escalation disabled")
	}
	cancel()
	<-done
}
