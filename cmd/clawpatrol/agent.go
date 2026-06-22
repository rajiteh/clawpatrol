package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// kubernetesDefaultTokenPath is the projected ServiceAccount token the
// kubernetes_token_review provider presents by default. Lives here (not
// in the linux-only file) because it's a cross-platform flag default.
const kubernetesDefaultTokenPath = "/var/run/secrets/tokens/clawpatrol-token"

// agentOptions configures `clawpatrol agent`: a resident, foreground,
// privileged data plane that self-enrolls through an authorizer, brings up
// a userspace WireGuard TUN, and routes the whole network namespace through
// the gateway. It stays up for the netns lifetime (the userspace device
// dies with the process) and deregisters best-effort on SIGTERM. The
// execution workload runs in a sibling, unprivileged container that shares
// this netns and reads the handoff files below.
type agentOptions struct {
	GatewayURL string

	// AuthorizerType/Name mirror the gateway's two-label authorizer block
	// `authorizer "<type>" "<name>"`. Type selects the client-side claims
	// provider (how identity is gathered); Name is what's sent on the wire
	// to pick the server authorizer.
	AuthorizerType string
	AuthorizerName string

	// KubeTokenPath is the kubernetes_token_review provider's credential.
	// Provider-scoped on purpose — not every authorizer authenticates with
	// a token file.
	KubeTokenPath string

	// Sibling-handoff outputs: files the unprivileged workload container
	// reads off the shared volume once the tunnel is up.
	EnvOut    string
	CAOut     string
	ReadyFile string

	Iface string
	MTU   int
}

// runAgent parses the `clawpatrol agent` flags and dispatches to the
// platform implementation. Kept cross-platform (no wireguard imports) so
// the flag surface and validation errors are identical everywhere; agentRun
// is linux-only.
func runAgent(args []string) {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	var (
		authorizer string
		opt        agentOptions
	)
	fs.StringVar(&opt.GatewayURL, "gateway-url", "", "gateway API URL, e.g. https://clawpatrol.clawpatrol.svc:8443")
	fs.StringVar(&authorizer, "authorizer", "", "enrollment authorizer to register through, as <type>/<name> (e.g. kubernetes_token_review/agents)")
	fs.StringVar(&opt.KubeTokenPath, "kubernetes-token-path", kubernetesDefaultTokenPath, "kubernetes_token_review: projected ServiceAccount token path")
	fs.StringVar(&opt.EnvOut, "env-out", "/clawpatrol/env", "path to write shell exports for the workload container")
	fs.StringVar(&opt.CAOut, "ca-out", "/clawpatrol/ca.crt", "path to write the gateway CA bundle")
	fs.StringVar(&opt.ReadyFile, "ready-file", "/clawpatrol/ready", "path to touch after network and env setup succeed")
	fs.StringVar(&opt.Iface, "iface", "clawpatrol0", "TUN interface name")
	fs.IntVar(&opt.MTU, "mtu", dynamicPeerDefaultMTU, "TUN MTU")
	_ = fs.Parse(args)

	if len(fs.Args()) > 0 {
		fail("clawpatrol agent does not take a command; the workload runs in a sibling container sharing this netns")
	}
	if strings.TrimSpace(opt.GatewayURL) == "" {
		fail("clawpatrol agent: --gateway-url is required")
	}
	typ, name, err := parseAgentAuthorizer(authorizer)
	if err != nil {
		fail("%v", err)
	}
	opt.AuthorizerType, opt.AuthorizerName = typ, name

	if err := agentRun(context.Background(), opt); err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol agent: %v\n", err)
		os.Exit(1)
	}
}

// preferV4 returns the first IPv4 address (unmapped), falling back to the
// first address of any family when there is no IPv4. The agent pins IPv4
// host routes by default and the gateway WireGuard endpoint is reached over
// IPv4 in typical clusters; dialing an IPv6 endpoint while only IPv4 is
// route-pinned would blackhole the handshake once the default route flips
// to the tunnel.
func preferV4(ips []netip.Addr) (netip.Addr, bool) {
	if len(ips) == 0 {
		return netip.Addr{}, false
	}
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), true
		}
	}
	return ips[0].Unmap(), true
}

// parseAgentAuthorizer splits the `--authorizer <type>/<name>` value,
// mirroring the gateway's `authorizer "<type>" "<name>"` block. The type
// selects the client claims provider; the name is sent on the wire.
func parseAgentAuthorizer(s string) (typ, name string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("--authorizer is required (form: <type>/<name>, e.g. kubernetes_token_review/agents)")
	}
	typ, name, ok := strings.Cut(s, "/")
	typ, name = strings.TrimSpace(typ), strings.TrimSpace(name)
	if !ok || typ == "" || name == "" {
		return "", "", fmt.Errorf("--authorizer %q must be <type>/<name>, e.g. kubernetes_token_review/agents", s)
	}
	if typ != dynamicPeerAuthorizerKubernetesTokenRev {
		return "", "", fmt.Errorf("unsupported authorizer type %q (supported: %s)", typ, dynamicPeerAuthorizerKubernetesTokenRev)
	}
	return typ, name, nil
}
