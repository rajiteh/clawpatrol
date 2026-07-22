//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// The route protocol tag (opt.RouteProto, default defaultRouteProto) turns the
// routing table itself into the bridge's durable state: every control-plane
// host route the bridge pins to the underlay (gateway API, WireGuard endpoint,
// DNS resolvers) carries it, so it survives the process exit and the container
// restart. A self-heal restart then recovers the underlay gateway from a
// tagged pin instead of a default route — there is no default route after
// self-heal, by design (see the selfHeal case in bridgeRun).

// bridgeRun is the resident, privileged data plane behind
// `clawpatrol bridge`. It self-enrolls through an authorizer, hosts a
// userspace WireGuard tunnel, routes the whole network namespace through the
// gateway, writes the CA + env handoff for the sibling workload container,
// and deregisters on SIGTERM. The enroll / deregister / claims logic is the
// transport-agnostic enrollment client core (enrollment_client.go);
// everything here is the TUN-specific bring-up.
func bridgeRun(ctx context.Context, opt bridgeOptions) error {
	claims, credential, err := gatherEnrollmentClaims(opt.AuthorizerType, opt.KubeTokenPath)
	if err != nil {
		return err
	}

	clientPrivB64, _, clientPubB64, err := wgGenKeypair()
	if err != nil {
		return fmt.Errorf("generate wireguard keypair: %w", err)
	}

	// The underlay route is the pod's original (pre-tunnel) default. On first
	// boot that is the live CNI default route. After a self-heal restart there
	// is no default route (self-heal leaves the netns fail-closed), so recover
	// it from a surviving tagged pin instead — the pins carry the same
	// via/dev. Either way we need it to pin the control-plane hosts to the
	// underlay before the default flips to the tunnel.
	route4, ok4 := discoverUnderlayRoute("-4", opt.RouteProto)
	if !ok4 {
		return fmt.Errorf("no usable underlay route: neither a default route nor a tagged clawpatrol pin was found")
	}
	// IPv6 is optional: present only when the pod already has a v6 underlay
	// route. We pin/replace v6 only in that case, so we never create a v6
	// default that would blackhole traffic that previously had no route.
	route6, have6 := discoverUnderlayRoute("-6", opt.RouteProto)

	// Resolvers the pod already uses (from /etc/resolv.conf). Pinning them to
	// the underlay keeps DNS working after the default flips to the tunnel and,
	// critically, after a self-heal restart when there is no default route —
	// so the sidecar can still resolve the gateway hostname by name (SNI/Host
	// stay correct) to re-enroll. Best-effort: empty when resolv.conf names no
	// nameservers.
	resolverIPs := resolvConfNameservers()
	registerResp, err := enrollmentRegister(ctx, opt.GatewayURL, credential, enrollmentRegisterRequest{
		Transport:          enrollmentTransportWireGuard,
		Authorizer:         opt.AuthorizerName,
		WireGuardPublicKey: clientPubB64,
		Claims:             claims,
		// The bridge hosts a resident tunnel and runs the liveness watchdog,
		// so it needs the gateway to keepalive back (symmetric) for its
		// rx-based self-heal to work.
		Keepalive: true,
	})
	if err != nil {
		return err
	}
	if registerResp.MTU != 0 {
		opt.MTU = registerResp.MTU
	}

	apiURL, err := url.Parse(opt.GatewayURL)
	if err != nil {
		return fmt.Errorf("gateway-url: %w", err)
	}
	// Fail fast rather than silently skip pinning the API host routes —
	// consistent with the fatal pin stance below; an unpinned API after the
	// default-route swap would blackhole the env-pushdown + deregister calls.
	apiIPs, err := lookupHostIPs(apiURL.Hostname())
	if err != nil {
		return fmt.Errorf("resolve gateway api host %q: %w", apiURL.Hostname(), err)
	}
	endpointIP, endpointAddr, err := resolveWGEndpoint(registerResp.Endpoint)
	if err != nil {
		return err
	}
	// Keep the gateway API + WG endpoint reachable on the original path once
	// the default route flips to the tunnel. A missed pin blackholes the
	// handshake / API calls, so a pin failure is fatal. v6 addresses are
	// pinned only when a v6 default route exists (the family we'll replace);
	// otherwise they keep their existing routing.
	for _, ip := range append(apiIPs, endpointIP) {
		if !ip.Is4() && !have6 {
			continue
		}
		if err := pinHostRoute(ip, route4, route6, have6, opt.RouteProto); err != nil {
			return fmt.Errorf("pin host route %s: %w", ip, err)
		}
	}
	// Pin the resolvers too, so DNS survives the default flip and a self-heal
	// restart. Best-effort: a resolver that can't be pinned (e.g. reachable
	// only through the tunnel) just falls back to normal routing rather than
	// failing bring-up.
	for _, ip := range resolverIPs {
		if !ip.Is4() && !have6 {
			continue
		}
		if err := pinHostRoute(ip, route4, route6, have6, opt.RouteProto); err != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol] bridge: pin resolver route %s: %v — continuing\n", ip, err)
		}
	}

	tunDev, err := wgtun.CreateTUN(opt.Iface, opt.MTU)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	defer func() { _ = tunDev.Close() }()
	ifaceName, err := tunDev.Name()
	if err != nil {
		return fmt.Errorf("tun name: %w", err)
	}
	logger := device.NewLogger(device.LogLevelError, "[clawpatrol tun wg] ")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	defer dev.Close()

	if err := setupTunDevice(ifaceName, opt.MTU, registerResp.PeerIP, registerResp.PeerIPv6); err != nil {
		return err
	}
	// The gateway dictates keepalive + reap horizon at enroll. Mirror the
	// keepalive onto our tunnel and size the watchdog's rx-liveness
	// thresholds from the same numbers so the client escalates in lock-step
	// with the gateway's reaper.
	keepaliveSecs := registerResp.KeepaliveIntervalSeconds
	if keepaliveSecs <= 0 {
		keepaliveSecs = 25
	}
	keepalive := time.Duration(keepaliveSecs) * time.Second
	var rxResetAfter, rxExitAfter time.Duration
	if mult := registerResp.KeepaliveReapCount; mult >= 2 {
		// Local rebuild after the client's configured missed-keepalive count
		// (default 2, disabled at 0 or when it meets/exceeds the reap
		// horizon); full restart at the reap horizon (mult missed). Positive
		// jitter (≤ half a keepalive) never fires early and staggers a mass
		// reap so sidecars don't all re-enroll at once.
		if rm := watchdogResetMisses(opt.LocalResetMisses, mult); rm > 0 {
			rxResetAfter = keepalive * time.Duration(rm)
		}
		jitter := time.Duration(rand.Int63n(int64(keepalive/2) + 1))
		rxExitAfter = keepalive*time.Duration(mult) + jitter
	}
	ipc, err := buildTunWGIpc(clientPrivB64, registerResp.ServerPublicKey, endpointAddr, keepaliveSecs)
	if err != nil {
		return err
	}
	if err := dev.IpcSet(ipc); err != nil {
		return fmt.Errorf("wg IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("wg up: %w", err)
	}
	if err := replaceDefaultRoutes(ifaceName, have6); err != nil {
		return err
	}

	watchdogCtx, stopWatchdog := context.WithCancel(context.Background())
	defer stopWatchdog()
	// selfHeal fires when the watchdog gives up on this enrollment (rx quiet
	// past the exit threshold). We handle it on the main goroutine rather
	// than os.Exit from the watchdog so the netns is cleaned up first — see
	// the wait below.
	selfHeal := make(chan struct{}, 1)
	watchdogTicker := time.NewTicker(wgWatchdogPoll)
	go func() {
		defer watchdogTicker.Stop()
		runWGWatchdogLoop(watchdogCtx, wgWatchdogConfig{
			stats: func() *wgPeerStats {
				uapi, err := dev.IpcGet()
				if err != nil {
					return nil
				}
				return parsePeerStats(uapi)
			},
			reset:         func() error { return dev.IpcSet(ipc) },
			log:           logger,
			tick:          watchdogTicker.C,
			resetCooldown: wgWatchdogResetCooldown,
			now:           time.Now,
			rxResetAfter:  rxResetAfter,
			rxExitAfter:   rxExitAfter,
			exit: func() {
				select {
				case selfHeal <- struct{}{}:
				default:
				}
			},
		})
	}()

	envVars, err := enrollmentFetchEnv(ctx, opt.GatewayURL, registerResp.APIToken)
	if err != nil {
		return err
	}
	envVars = append(caPathPushdownVars(opt.CAOut), envVars...)
	if err := writeTunFiles(opt, envVars, registerResp.CAPEM); err != nil {
		return err
	}

	// Stay up for the netns lifetime. WireGuard persistent-keepalive keeps
	// the tunnel live and lets the gateway observe liveness (rx_bytes); the
	// gateway reaps the peer if we go quiet. No app-level heartbeat.
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-sigCtx.Done():
		// Graceful shutdown: the pod is terminating, so best-effort
		// deregister (bounded so a hung gateway/DNS call can't delay pod
		// termination past the grace period). The netns is torn down with
		// the pod, so there is nothing to restore.
		delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		enrollmentDeregister(delCtx, opt.GatewayURL, registerResp.APIToken)
		return nil
	case <-selfHeal:
		// The watchdog gave up on this enrollment (peer reaped or
		// partitioned). The pod keeps running. We deliberately do NOT restore
		// a broad default route: doing so would let the workload's general
		// egress leave untunneled during the gap before the restarted sidecar
		// rebuilds the tunnel. Instead we let the `default dev clawpatrol0`
		// route die with the interface on exit — off-link egress then has no
		// route (fail closed). The kubelet restarts this native sidecar; it
		// recovers the underlay gateway from the tagged control-plane pins
		// (which survive on eth0) and re-enrolls with a fresh key over them.
		// Skip deregister: the peer is already gone. Exit non-zero to trigger
		// the restart.
		stopWatchdog()
		return errBridgeSelfHeal
	}
}

// errBridgeSelfHeal is returned by bridgeRun when the watchdog decides the
// enrollment is gone and the sidecar must restart to re-enroll. It is an
// expected, non-fatal outcome (the kubelet restarts the native sidecar), not
// a crash — but it exits non-zero to trigger that restart.
var errBridgeSelfHeal = errors.New("bridge: peer liveness lost; restarting to re-enroll")

func buildTunWGIpc(privateKeyB64, serverPublicKeyB64, endpoint string, keepaliveSeconds int) (string, error) {
	privHex, err := base64DecodeToHex(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pubRaw, err := normalizeWGPublicKey(serverPublicKeyB64)
	if err != nil {
		return "", fmt.Errorf("server public key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pubRaw)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	// The gateway dictates the keepalive cadence at enroll and keeps its own
	// side in sync; fall back to 25s only if the response omitted it (older
	// gateway). Keepalive drives the gateway's rx_bytes liveness in one
	// direction and the sidecar's watchdog in the other.
	if keepaliveSeconds <= 0 {
		keepaliveSeconds = 25
	}
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepaliveSeconds)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	return b.String(), nil
}

func setupTunDevice(iface string, mtu int, peerIP, peerIPv6 string) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up"},
		{"ip", "addr", "replace", peerIP + "/32", "dev", iface},
	}
	for _, step := range steps {
		if err := runIP(step...); err != nil {
			return err
		}
	}
	// IPv6 is best-effort: a netns without IPv6 (e.g. the host booted with
	// ipv6.disable=1) must still bring up the v4 tunnel. This mirrors the
	// optional v6 default route in replaceDefaultRoutes and the child-netns
	// degradation in run_linux.go — never let a missing v6 stack be fatal.
	if peerIPv6 != "" {
		if err := runIP("ip", "-6", "addr", "replace", peerIPv6+"/128", "dev", iface); err != nil {
			fmt.Fprintf(os.Stderr, "[clawpatrol] bridge: ip -6 addr replace %s/128 dev %s: %v — continuing without IPv6 in the sandbox\n", peerIPv6, iface, err)
		}
	}
	return nil
}

// discoverUnderlayRoute resolves the pod's pre-tunnel route for a family
// ("-4" / "-6"). It prefers the live default route (the normal first-boot
// case) and falls back to a surviving tagged clawpatrol pin, which is how a
// self-heal restart recovers the underlay gateway when there is no default
// route left. Returns false when neither is available (for v4 that's fatal to
// bring-up; for v6 it just means "no IPv6 underlay", same as before).
func discoverUnderlayRoute(family, proto string) (linuxDefaultRoute, bool) {
	if out, err := exec.Command("ip", family, "route", "show", "default").Output(); err == nil {
		if r, err := parseDefaultRoute(out); err == nil && r.Dev != "" {
			return r, true
		}
	}
	// No usable default (self-heal restart). Recover via/dev from a pin we
	// tagged on first boot; they live on the underlay device and survive.
	out, err := exec.Command("ip", family, "route", "show", "proto", proto).Output()
	if err != nil {
		return linuxDefaultRoute{}, false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if r, err := parsePinnedRoute(line); err == nil && r.Dev != "" {
			return r, true
		}
	}
	return linuxDefaultRoute{}, false
}

// parsePinnedRoute extracts the via/dev from one `ip route show proto` line
// (e.g. "10.96.0.1 via 10.244.0.1 dev eth0 proto 111"). Unlike a default
// route, the leading token is the pinned host, so we only read via/dev.
func parsePinnedRoute(line string) (linuxDefaultRoute, error) {
	fields := strings.Fields(line)
	var r linuxDefaultRoute
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			r.Via = fields[i+1]
		case "dev":
			r.Dev = fields[i+1]
		}
	}
	if r.Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("no dev in route line %q", line)
	}
	return r, nil
}

// resolvConfNameservers returns the nameserver IPs from /etc/resolv.conf.
// resolv.conf nameservers are always IP literals, so each parses cleanly; a
// missing or nameserver-less file yields nil (DNS pinning is best-effort).
func resolvConfNameservers() []netip.Addr {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip, err := netip.ParseAddr(fields[1]); err == nil {
				out = append(out, ip)
			}
		}
	}
	return out
}

func replaceDefaultRoutes(iface string, replace6 bool) error {
	if err := runIP("ip", "route", "replace", "default", "dev", iface); err != nil {
		return err
	}
	if replace6 {
		// Only tunnel v6 when the pod already had a v6 default route — never
		// create one, which would blackhole v6 that previously had no route.
		_ = runIP("ip", "-6", "route", "replace", "default", "dev", iface)
	}
	return nil
}

type linuxDefaultRoute struct {
	Dev string
	Via string
}

func parseDefaultRoute(out []byte) (linuxDefaultRoute, error) {
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return linuxDefaultRoute{}, fmt.Errorf("no default route")
	}
	var r linuxDefaultRoute
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "via":
			r.Via = fields[i+1]
		case "dev":
			r.Dev = fields[i+1]
		}
	}
	if r.Dev == "" {
		return linuxDefaultRoute{}, fmt.Errorf("default route has no dev: %s", strings.TrimSpace(string(out)))
	}
	return r, nil
}

func pinHostRoute4(ip netip.Addr, route linuxDefaultRoute, proto string) error {
	dst := ip.String() + "/32"
	args := []string{"ip", "route", "replace", dst}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev, "proto", proto)
	return runIP(args...)
}

func pinHostRoute6(ip netip.Addr, route linuxDefaultRoute, proto string) error {
	dst := ip.String() + "/128"
	args := []string{"ip", "-6", "route", "replace", dst}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev, "proto", proto)
	return runIP(args...)
}

// pinHostRoute pins ip to its family's pre-tunnel default route, tagged with
// proto so it can be recovered after a self-heal restart.
func pinHostRoute(ip netip.Addr, route4, route6 linuxDefaultRoute, have6 bool, proto string) error {
	if ip.Is4() {
		return pinHostRoute4(ip, route4, proto)
	}
	if !have6 {
		return fmt.Errorf("no IPv6 default route to pin %s", ip)
	}
	return pinHostRoute6(ip, route6, proto)
}

// resolveWGEndpoint resolves the WireGuard endpoint host:port to a concrete
// ip:port, preferring IPv4 (see preferV4). Returns the chosen IP so the
// caller can pin a host route to it before the default route flips to the
// tunnel.
func resolveWGEndpoint(endpoint string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("endpoint %q: %w", endpoint, err)
	}
	ips, err := lookupHostIPs(host)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	ip, ok := preferV4(ips)
	if !ok {
		return netip.Addr{}, "", fmt.Errorf("resolve endpoint %q: no A/AAAA records", host)
	}
	return ip, net.JoinHostPort(ip.String(), port), nil
}

func lookupHostIPs(host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			// Unmap 4-in-6 so Is4()/family checks and route pinning behave.
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}

func runIP(args ...string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func writeTunFiles(opt bridgeOptions, vars []pushdownEnvVar, caPEM string) error {
	if err := os.MkdirAll(filepath.Dir(opt.EnvOut), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opt.CAOut), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opt.ReadyFile), 0o755); err != nil {
		return err
	}
	if caPEM != "" {
		if err := os.WriteFile(opt.CAOut, []byte(caPEM), 0o644); err != nil {
			return fmt.Errorf("write ca: %w", err)
		}
	}
	var buf bytes.Buffer
	for _, ev := range vars {
		if ev.Name == "" {
			continue
		}
		fmt.Fprintf(&buf, "export %s=%q\n", ev.Name, ev.Value)
	}
	if err := os.WriteFile(opt.EnvOut, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write env: %w", err)
	}
	if err := os.WriteFile(opt.ReadyFile, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write ready: %w", err)
	}
	return nil
}
