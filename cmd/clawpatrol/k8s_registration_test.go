package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
)

func TestNormalizeWGPublicKey(t *testing.T) {
	_, pubHex, pubB64, err := wgGenKeypair()
	if err != nil {
		t.Fatalf("wgGenKeypair: %v", err)
	}
	if got, err := normalizeWGPublicKey(pubHex); err != nil || got != pubHex {
		t.Fatalf("hex normalize = %q, %v; want %q", got, err, pubHex)
	}
	if got, err := normalizeWGPublicKey(pubB64); err != nil || got != pubHex {
		t.Fatalf("base64 normalize = %q, %v; want %q", got, err, pubHex)
	}
	if _, err := normalizeWGPublicKey("not-a-key"); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestK8sServiceAccountAndAllowlist(t *testing.T) {
	ns, sa, ok := serviceAccountFromUsername("system:serviceaccount:agents:agent-runner")
	if !ok || ns != "agents" || sa != "agent-runner" {
		t.Fatalf("serviceAccountFromUsername = %q, %q, %v", ns, sa, ok)
	}
	if _, _, ok := serviceAccountFromUsername("alice@example.com"); ok {
		t.Fatal("non-serviceaccount username accepted")
	}
	cfg := &config.EnrollmentAuthorizerBlock{
		Allow: []config.EnrollmentAllow{{
			Namespace:      "agents",
			ServiceAccount: "agent-runner",
			Profiles:       []string{"default", "prod"},
		}},
	}
	if !k8sRegistrationAllowed(cfg, "agents", "agent-runner", "prod") {
		t.Fatal("expected allow")
	}
	if k8sRegistrationAllowed(cfg, "agents", "other", "prod") {
		t.Fatal("wrong serviceaccount allowed")
	}
	if k8sRegistrationAllowed(cfg, "agents", "agent-runner", "admin") {
		t.Fatal("wrong profile allowed")
	}
}

type fakeK8sVerifier func(context.Context, string, k8sEnrollmentClaims, *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error)

func (f fakeK8sVerifier) VerifyPod(ctx context.Context, token string, claims k8sEnrollmentClaims, cfg *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error) {
	return f(ctx, token, claims, cfg)
}

func TestKubernetesTokenReviewAuthorizerIdentity(t *testing.T) {
	cfg := &config.EnrollmentAuthorizerBlock{Name: "agents"}
	claims, err := json.Marshal(k8sEnrollmentClaims{
		PodName:      "agent-1",
		PodNamespace: "agents",
		PodUID:       "uid-1",
		NodeName:     "kind-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := &kubernetesTokenReviewAuthorizer{
		name: "agents",
		cfg:  cfg,
		verifier: fakeK8sVerifier(func(_ context.Context, token string, got k8sEnrollmentClaims, _ *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error) {
			if token != "pod-token" {
				t.Fatalf("token = %q, want pod-token", token)
			}
			if got.PodUID != "uid-1" {
				t.Fatalf("claims = %+v", got)
			}
			return k8sVerifiedPod{
				Namespace:      got.PodNamespace,
				Name:           got.PodName,
				UID:            got.PodUID,
				ServiceAccount: "agent-runner",
				Profile:        "default",
				NodeName:       got.NodeName,
			}, nil
		}),
	}
	id, err := auth.Authorize(context.Background(), "pod-token", claims)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if id.SubjectKey != "kubernetes:agents:uid-1" {
		t.Fatalf("subject key = %q", id.SubjectKey)
	}
	if id.ReplacementKey != "kubernetes:agents:agent-1" {
		t.Fatalf("replacement key = %q", id.ReplacementKey)
	}
	if id.DisplayName != "agents/agent-1" || id.Owner != "system:serviceaccount:agents:agent-runner" || id.Profile != "default" {
		t.Fatalf("identity = %+v", id)
	}
}

// cleanupEnrolledPeerLocked tears down every trace of an enrolled peer:
// the WireGuard peer (and its wg_peers row), the API token, and the
// device/agent registry entries.
func TestCleanupEnrolledPeer(t *testing.T) {
	g := newEnrollmentTestGateway(t)
	startEnrollmentTestWGServer(t, g)

	resp, err := registerFor(t, g, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := g.enrolledPeerByIP(resp.PeerIP); err != nil {
		t.Fatalf("precondition: enrolled peer not present: %v", err)
	}

	g.enrollmentMu.Lock()
	g.cleanupEnrolledPeerLocked(context.Background(), resp.PeerIP)
	g.enrollmentMu.Unlock()

	if _, err := g.enrolledPeerByIP(resp.PeerIP); err == nil {
		t.Fatal("enrolled peer still present after cleanup")
	}
	if got := wgPeerRowsForIP(t, g, resp.PeerIP); got != 0 {
		t.Fatalf("wg_peers rows after cleanup = %d, want 0", got)
	}
	if got := peerIPForAPIToken(g.db, resp.APIToken); got != "" {
		t.Fatalf("peer API token still resolves to %q", got)
	}
	if g.onboard.HasDevice(resp.PeerIP) {
		t.Fatal("device row still present after cleanup")
	}
}
