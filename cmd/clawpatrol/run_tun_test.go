package main

import "testing"

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
		// --tun after `--` belongs to the wrapped command, not run.
		{[]string{"--", "agent", "--tun"}, false},
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
