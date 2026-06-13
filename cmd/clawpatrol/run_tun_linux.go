//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
// heartbeats the lease, and deregisters on SIGTERM.
func tunModeRun(ctx context.Context, opt tunModeOptions) error {
	// The authorizer type selects how identity is gathered. v1 ships one
	// provider; the switch is the seam future providers plug into.
	var (
		claims  json.RawMessage
		saToken string
		err     error
	)
	switch opt.AuthorizerType {
	case dynamicPeerAuthorizerKubernetesTokenRev:
		claims, saToken, err = kubernetesProviderClaims(opt)
	default:
		return fmt.Errorf("unsupported dynamic peer authorizer type %q", opt.AuthorizerType)
	}
	if err != nil {
		return err
	}

	clientPrivB64, _, clientPubB64, err := wgGenKeypair()
	if err != nil {
		return fmt.Errorf("generate wireguard keypair: %w", err)
	}

	route, err := defaultRoute4()
	if err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	registerResp, err := tunModeRegister(ctx, opt.GatewayURL, saToken, dynamicPeerRegisterRequest{
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
	apiIPs, _ := lookupHostIPs(apiURL.Hostname())
	endpointIP, endpointAddr, err := resolveWGEndpoint(registerResp.Endpoint)
	if err != nil {
		return err
	}
	for _, ip := range append(apiIPs, endpointIP) {
		if ip.Is4() {
			_ = pinHostRoute4(ip, route)
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
	if err := replaceDefaultRoutes(ifaceName); err != nil {
		return err
	}

	envVars, err := tunModeFetchEnv(ctx, opt.GatewayURL, registerResp.APIToken)
	if err != nil {
		return err
	}
	envVars = append(caPathPushdownVars(opt.CAOut), envVars...)
	if err := writeTunFiles(opt, envVars, registerResp.CAPEM); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go tunModeHeartbeatLoop(ctx, opt.GatewayURL, registerResp.APIToken, registerResp.LeaseTTLSeconds)
	<-ctx.Done()
	tunModeDelete(context.Background(), opt.GatewayURL, registerResp.APIToken)
	return nil
}

// kubernetesProviderClaims gathers the kubernetes_token_review identity:
// claims from the downward-API POD_* env, credential from the projected
// ServiceAccount token.
func kubernetesProviderClaims(opt tunModeOptions) (json.RawMessage, string, error) {
	podName := os.Getenv("POD_NAME")
	podNamespace := os.Getenv("POD_NAMESPACE")
	podUID := os.Getenv("POD_UID")
	nodeName := os.Getenv("NODE_NAME")
	if podName == "" || podNamespace == "" || podUID == "" {
		return nil, "", fmt.Errorf("POD_NAME, POD_NAMESPACE, and POD_UID must be supplied by the Downward API")
	}
	tokenBytes, err := os.ReadFile(opt.KubeTokenPath)
	if err != nil {
		return nil, "", fmt.Errorf("read serviceaccount token: %w", err)
	}
	claims, err := json.Marshal(k8sDynamicPeerClaims{
		PodName:      podName,
		PodNamespace: podNamespace,
		PodUID:       podUID,
		NodeName:     nodeName,
	})
	if err != nil {
		return nil, "", err
	}
	return claims, strings.TrimSpace(string(tokenBytes)), nil
}

func tunModeRegister(ctx context.Context, gatewayURL, token string, reqBody dynamicPeerRegisterRequest) (dynamicPeerRegisterResponse, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(reqBody); err != nil {
		return dynamicPeerRegisterResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(gatewayURL, "/")+dynamicPeerRegisterPath, &buf)
	if err != nil {
		return dynamicPeerRegisterResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return dynamicPeerRegisterResponse{}, fmt.Errorf("register: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return dynamicPeerRegisterResponse{}, fmt.Errorf("register status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out dynamicPeerRegisterResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return dynamicPeerRegisterResponse{}, fmt.Errorf("register decode: %w", err)
	}
	if out.Transport != dynamicPeerTransportWireGuard {
		return dynamicPeerRegisterResponse{}, fmt.Errorf("register response has unsupported transport %q", out.Transport)
	}
	if out.PeerIP == "" || out.ServerPublicKey == "" || out.Endpoint == "" || out.APIToken == "" {
		return dynamicPeerRegisterResponse{}, fmt.Errorf("register response missing peer_ip, server_public_key, endpoint, or api_token")
	}
	if out.LeaseTTLSeconds <= 0 {
		return dynamicPeerRegisterResponse{}, fmt.Errorf("register response has invalid lease_ttl_seconds")
	}
	return out, nil
}

func tunModeFetchEnv(ctx context.Context, gatewayURL, apiToken string) ([]pushdownEnvVar, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(gatewayURL, "/")+"/api/env-pushdown", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch env-pushdown: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch env-pushdown status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseEnvPushdownJSON(raw)
}

func tunModeHeartbeatLoop(ctx context.Context, gatewayURL, apiToken string, ttlSeconds int) {
	interval := time.Duration(ttlSeconds) * time.Second / 2
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(gatewayURL, "/")+dynamicPeerHeartbeatPath, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+apiToken)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
			}
		}
	}
}

func tunModeDelete(ctx context.Context, gatewayURL, apiToken string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, strings.TrimRight(gatewayURL, "/")+dynamicPeerRegisterPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}
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

func replaceDefaultRoutes(iface string) error {
	if err := runIP("ip", "route", "replace", "default", "dev", iface); err != nil {
		return err
	}
	_ = runIP("ip", "-6", "route", "replace", "default", "dev", iface)
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
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return linuxDefaultRoute{}, fmt.Errorf("no IPv4 default route")
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

func resolveWGEndpoint(endpoint string) (netip.Addr, string, error) {
	resolved, err := resolveEndpoint(endpoint)
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("resolve endpoint: %w", err)
	}
	host, _, err := net.SplitHostPort(resolved)
	if err != nil {
		return netip.Addr{}, "", err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, "", err
	}
	return ip, resolved, nil
}

func lookupHostIPs(host string) ([]netip.Addr, error) {
	if host == "" {
		return nil, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr)
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
