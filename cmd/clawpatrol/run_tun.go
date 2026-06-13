package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// kubernetesDefaultTokenPath is the projected ServiceAccount token the
// kubernetes_token_review provider presents by default. Lives here (not
// in the linux-only file) because it's a cross-platform flag default.
const kubernetesDefaultTokenPath = "/var/run/secrets/tokens/clawpatrol-token"

// tunModeOptions configures `clawpatrol run --tun`: a resident, privileged
// data plane that brings up a real TUN, routes the whole network namespace
// through the gateway, and (in dynamic-peer mode) self-registers + holds a
// lease. The execution workload runs in a sibling, unprivileged container
// that shares this netns.
type tunModeOptions struct {
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

// tunModeRequested reports whether `clawpatrol run` should enter tun mode.
// It scans only the flag section (anything before `--`, after which args
// belong to the wrapped command) for --tun or --dynamic-peer-authorizer.
func tunModeRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch name {
		case "tun":
			// Honor an explicit boolean value so `run --tun=false -- <cmd>`
			// stays on the normal (gVisor) path instead of dispatching here
			// and erroring. A bare `--tun` means true; an unparseable value
			// is left for the flag parser to reject.
			if !hasValue {
				return true
			}
			b, err := strconv.ParseBool(value)
			if err != nil || b {
				return true
			}
			// explicit false → not requested
		case "dynamic-peer-authorizer":
			return true
		}
	}
	return false
}

// runTunMode parses the tun-mode flags and dispatches to the platform
// implementation. Kept cross-platform (no wireguard imports) so the flag
// surface and validation errors are identical everywhere; tunModeRun is
// linux-only.
func runTunMode(args []string) {
	fs := flag.NewFlagSet("run --tun", flag.ExitOnError)
	var (
		tun        bool
		authorizer string
		opt        tunModeOptions
	)
	fs.BoolVar(&tun, "tun", false, "bring up a real TUN and route the whole network namespace through the gateway (privileged; default is per-process gVisor routing)")
	fs.StringVar(&opt.GatewayURL, "gateway-url", "", "gateway API URL, e.g. https://clawpatrol.clawpatrol.svc:8443")
	fs.StringVar(&authorizer, "dynamic-peer-authorizer", "", "self-register as a dynamic peer using the named gateway authorizer, as <type>/<name> (e.g. kubernetes_token_review/agents)")
	fs.StringVar(&opt.KubeTokenPath, "kubernetes-token-path", kubernetesDefaultTokenPath, "kubernetes_token_review: projected ServiceAccount token path")
	fs.StringVar(&opt.EnvOut, "env-out", "/clawpatrol/env", "path to write shell exports for the workload container")
	fs.StringVar(&opt.CAOut, "ca-out", "/clawpatrol/ca.crt", "path to write the gateway CA bundle")
	fs.StringVar(&opt.ReadyFile, "ready-file", "/clawpatrol/ready", "path to touch after network and env setup succeed")
	fs.StringVar(&opt.Iface, "tun-iface", "clawpatrol0", "TUN interface name")
	fs.IntVar(&opt.MTU, "tun-mtu", dynamicPeerDefaultMTU, "TUN MTU")
	_ = fs.Parse(args)

	if !tun {
		// --dynamic-peer-authorizer routed us here without --tun. The
		// unprivileged gVisor self-registration path is not implemented
		// yet; for now dynamic-peer mode requires the TUN transport.
		fail("--dynamic-peer-authorizer currently requires --tun")
	}
	if len(fs.Args()) > 0 {
		fail("run --tun does not take a wrapped command yet; the workload runs in a sibling container sharing this netns")
	}
	if strings.TrimSpace(opt.GatewayURL) == "" {
		fail("run --tun: --gateway-url is required")
	}
	typ, name, err := parseDynamicPeerAuthorizer(authorizer)
	if err != nil {
		fail("%v", err)
	}
	opt.AuthorizerType, opt.AuthorizerName = typ, name

	if err := tunModeRun(context.Background(), opt); err != nil {
		fmt.Fprintf(os.Stderr, "clawpatrol run --tun: %v\n", err)
		os.Exit(1)
	}
}

// preferV4 returns the first IPv4 address (unmapped), falling back to the
// first address of any family when there is no IPv4. The tun-mode sidecar
// pins IPv4 host routes by default and the gateway WireGuard endpoint is
// reached over IPv4 in typical clusters; dialing an IPv6 endpoint while only
// IPv4 is route-pinned would blackhole the handshake once the default route
// flips to the tunnel.
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

// parseDynamicPeerAuthorizer splits the `<type>/<name>` value, mirroring the
// gateway's `authorizer "<type>" "<name>"` block. The type selects the
// client claims provider; the name is sent on the wire.
func parseDynamicPeerAuthorizer(s string) (typ, name string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", fmt.Errorf("--dynamic-peer-authorizer is required (form: <type>/<name>, e.g. kubernetes_token_review/agents)")
	}
	typ, name, ok := strings.Cut(s, "/")
	typ, name = strings.TrimSpace(typ), strings.TrimSpace(name)
	if !ok || typ == "" || name == "" {
		return "", "", fmt.Errorf("--dynamic-peer-authorizer %q must be <type>/<name>, e.g. kubernetes_token_review/agents", s)
	}
	if typ != dynamicPeerAuthorizerKubernetesTokenRev {
		return "", "", fmt.Errorf("unsupported dynamic peer authorizer type %q (supported: %s)", typ, dynamicPeerAuthorizerKubernetesTokenRev)
	}
	return typ, name, nil
}
