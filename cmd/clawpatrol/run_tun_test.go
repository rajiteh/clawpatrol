package main

import (
	"net/netip"
	"testing"
)

func TestPreferV4(t *testing.T) {
	v4 := netip.MustParseAddr("10.55.0.2")
	v6 := netip.MustParseAddr("fd00::1")
	v4in6 := netip.MustParseAddr("::ffff:10.55.0.2")

	if got, ok := preferV4([]netip.Addr{v6, v4}); !ok || got != v4 {
		t.Fatalf("preferV4([v6,v4]) = %v (ok=%v), want %v", got, ok, v4)
	}
	if got, ok := preferV4([]netip.Addr{v6}); !ok || got != v6 {
		t.Fatalf("preferV4(v6-only) = %v (ok=%v), want %v", got, ok, v6)
	}
	if got, ok := preferV4([]netip.Addr{v4in6}); !ok || !got.Is4() || got != v4 {
		t.Fatalf("preferV4(4-in-6) = %v (ok=%v), want unmapped %v", got, ok, v4)
	}
	if _, ok := preferV4(nil); ok {
		t.Fatal("preferV4(nil) should be ok=false")
	}
}

func TestTunModeRequested(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{nil, false},
		{[]string{"--no-auto-expose", "--", "bash"}, false},
		{[]string{"--tun", "--gateway-url", "x"}, true},
		{[]string{"--tun=true"}, true},
		{[]string{"-tun"}, true},
		{[]string{"--dynamic-peer-authorizer", "kubernetes_token_review/agents"}, true},
		// Explicit false keeps run on the normal (gVisor) path.
		{[]string{"--tun=false", "--", "bash"}, false},
		{[]string{"-tun=0"}, false},
		// ...but an authorizer still requests tun dispatch (where it errors
		// "requires --tun"), even alongside --tun=false.
		{[]string{"--tun=false", "--dynamic-peer-authorizer", "kubernetes_token_review/agents"}, true},
		// --tun after `--` belongs to the wrapped command, not run.
		{[]string{"--", "agent", "--tun"}, false},
		{[]string{"--", "agent", "--tun=false"}, false},
	}
	for _, c := range cases {
		if got := tunModeRequested(c.args); got != c.want {
			t.Errorf("tunModeRequested(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}

func TestParseDynamicPeerAuthorizer(t *testing.T) {
	typ, name, err := parseDynamicPeerAuthorizer("kubernetes_token_review/agents")
	if err != nil || typ != "kubernetes_token_review" || name != "agents" {
		t.Fatalf("parse = %q %q %v", typ, name, err)
	}
	for _, bad := range []string{"", "agents", "kubernetes_token_review/", "/agents", "oidc/agents"} {
		if _, _, err := parseDynamicPeerAuthorizer(bad); err == nil {
			t.Errorf("parseDynamicPeerAuthorizer(%q) expected error", bad)
		}
	}
}
