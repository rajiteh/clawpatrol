//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
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

// tunModeRun is the resident, privileged data plane behind
// `clawpatrol run --tun`. It self-registers as a dynamic peer, brings up a
// userspace WireGuard TUN, routes the whole network namespace through the
// gateway, writes the CA + env handoff for the sibling workload container,
// heartbeats the lease, and deregisters on SIGTERM. The register /
// heartbeat / deregister / claims logic is the transport-agnostic
// dynamic-peer client core (dynamic_peer_client.go); everything here is
// the TUN-specific bring-up.
func tunModeRun(ctx context.Context, opt tunModeOptions) error {
	claims, credential, err := gatherDynamicPeerClaims(opt.AuthorizerType, opt.KubeTokenPath)
	if err != nil {
		return err
	}

	clientPrivB64, _, clientPubB64, err := wgGenKeypair()
	if err != nil {
		return fmt.Errorf("generate wireguard keypair: %w", err)
	}

	route4, err := defaultRoute4()
	if err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	// IPv6 is optional: present only when the pod already has a v6 default
	// route. We pin/replace v6 only in that case, so we never create a v6
	// default that would blackhole traffic that previously had no route.
	route6, have6 := defaultRoute6()
	registerResp, err := dynamicPeerRegister(ctx, opt.GatewayURL, credential, dynamicPeerRegisterRequest{
		Transport:          dynamicPeerTransportWireGuard,
		Authorizer:         opt.AuthorizerName,
		WireGuardPublicKey: clientPubB64,
		Claims:             claims,
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
	// default-route swap would blackhole heartbeats.
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
	// handshake / heartbeat, so a pin failure is fatal. v6 addresses are
	// pinned only when a v6 default route exists (the family we'll replace);
	// otherwise they keep their existing routing.
	for _, ip := range append(apiIPs, endpointIP) {
		if !ip.Is4() && !have6 {
			continue
		}
		if err := pinHostRoute(ip, route4, route6, have6); err != nil {
			return fmt.Errorf("pin host route %s: %w", ip, err)
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
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "[clawpatrol tun wg] "))
	defer dev.Close()

	if err := setupTunDevice(ifaceName, opt.MTU, registerResp.PeerIP, registerResp.PeerIPv6); err != nil {
		return err
	}
	ipc, err := buildTunWGIpc(clientPrivB64, registerResp.ServerPublicKey, endpointAddr)
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

	envVars, err := dynamicPeerFetchEnv(ctx, opt.GatewayURL, registerResp.APIToken)
	if err != nil {
		return err
	}
	envVars = append(caPathPushdownVars(opt.CAOut), envVars...)
	if err := writeTunFiles(opt, envVars, registerResp.CAPEM); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go dynamicPeerHeartbeatLoop(ctx, opt.GatewayURL, registerResp.APIToken, registerResp.LeaseTTLSeconds)
	<-ctx.Done()
	// Best-effort deregister, bounded so a hung gateway/DNS call can't delay
	// pod termination past the grace period (the lease still TTL-expires).
	delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dynamicPeerDeregister(delCtx, opt.GatewayURL, registerResp.APIToken)
	return nil
}

func buildTunWGIpc(privateKeyB64, serverPublicKeyB64, endpoint string) (string, error) {
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
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	return b.String(), nil
}

func setupTunDevice(iface string, mtu int, peerIP, peerIPv6 string) error {
	steps := [][]string{
		{"ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu), "up"},
		{"ip", "addr", "replace", peerIP + "/32", "dev", iface},
	}
	if peerIPv6 != "" {
		steps = append(steps, []string{"ip", "-6", "addr", "replace", peerIPv6 + "/128", "dev", iface})
	}
	for _, step := range steps {
		if err := runIP(step...); err != nil {
			return err
		}
	}
	return nil
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

func defaultRoute4() (linuxDefaultRoute, error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return linuxDefaultRoute{}, err
	}
	return parseDefaultRoute(out)
}

// defaultRoute6 returns the IPv6 default route, and false when the pod has
// none (single-stack v4). A missing v6 default is not an error — the sidecar
// leaves v6 untouched in that case.
func defaultRoute6() (linuxDefaultRoute, bool) {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return linuxDefaultRoute{}, false
	}
	r, err := parseDefaultRoute(out)
	if err != nil {
		return linuxDefaultRoute{}, false
	}
	return r, true
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

func pinHostRoute4(ip netip.Addr, route linuxDefaultRoute) error {
	dst := ip.String() + "/32"
	args := []string{"ip", "route", "replace", dst}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev)
	return runIP(args...)
}

func pinHostRoute6(ip netip.Addr, route linuxDefaultRoute) error {
	dst := ip.String() + "/128"
	args := []string{"ip", "-6", "route", "replace", dst}
	if route.Via != "" {
		args = append(args, "via", route.Via)
	}
	args = append(args, "dev", route.Dev)
	return runIP(args...)
}

// pinHostRoute pins ip to its family's pre-tunnel default route.
func pinHostRoute(ip netip.Addr, route4, route6 linuxDefaultRoute, have6 bool) error {
	if ip.Is4() {
		return pinHostRoute4(ip, route4)
	}
	if !have6 {
		return fmt.Errorf("no IPv6 default route to pin %s", ip)
	}
	return pinHostRoute6(ip, route6)
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

func writeTunFiles(opt tunModeOptions, vars []pushdownEnvVar, caPEM string) error {
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
