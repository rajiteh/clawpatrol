package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

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

type fakeK8sVerifier func(context.Context, string, k8sDynamicPeerClaims, *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error)

func (f fakeK8sVerifier) VerifyPod(ctx context.Context, token string, claims k8sDynamicPeerClaims, cfg *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error) {
	return f(ctx, token, claims, cfg)
}

func TestKubernetesTokenReviewAuthorizerIdentity(t *testing.T) {
	cfg := &config.EnrollmentAuthorizerBlock{Name: "agents"}
	claims, err := json.Marshal(k8sDynamicPeerClaims{
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
		verifier: fakeK8sVerifier(func(_ context.Context, token string, got k8sDynamicPeerClaims, _ *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error) {
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

func TestDynamicPeerLeaseRefreshAndCleanup(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer func() { _ = db.Close() }()
	g := &Gateway{db: db, onboard: newOnboardRegistry(), agents: NewAgentRegistry()}
	if err := g.onboard.Load(db); err != nil {
		t.Fatalf("onboard load: %v", err)
	}
	startDynamicPeerTestWGServer(t, g)

	lease := dynamicPeerLease{
		PeerIP:             "10.55.0.42",
		Transport:          dynamicPeerTransportWireGuard,
		AuthorizerType:     dynamicPeerAuthorizerKubernetesTokenRev,
		AuthorizerName:     "agents",
		SubjectKey:         "kubernetes:agents:uid-1",
		ReplacementKey:     "kubernetes:agents:agent-1",
		DisplayName:        "agents/agent-1",
		Owner:              "system:serviceaccount:agents:agent-runner",
		Profile:            "default",
		WireGuardPublicKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		MetadataJSON:       "{}",
		ExpiresNS:          time.Now().Add(time.Minute).UnixNano(),
		LastHeartbeatNS:    time.Now().UnixNano(),
	}
	if err := upsertDynamicPeerLease(db, lease); err != nil {
		t.Fatalf("upsert lease: %v", err)
	}
	token, err := mintAndPersistPeerAPIToken(db, lease.PeerIP)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	g.onboard.AssignProfile(lease.PeerIP, lease.Profile)
	g.onboard.SetHostname(lease.PeerIP, "agents/agent-1")
	g.agents.Seed(lease.PeerIP)

	refreshed, err := g.refreshDynamicPeerLease(context.Background(), lease.PeerIP, 2*time.Minute)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.ExpiresNS <= lease.ExpiresNS {
		t.Fatalf("refresh did not extend expiry")
	}

	_, err = db.Exec("UPDATE dynamic_peer_leases SET expires_ns = ? WHERE peer_ip = ?", time.Now().Add(-time.Second).UnixNano(), lease.PeerIP)
	if err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	g.sweepExpiredDynamicPeerLeases()
	if _, err := g.dynamicPeerLeaseByIP(lease.PeerIP); err == nil {
		t.Fatal("expired lease still present")
	}
	if got := peerIPForAPIToken(db, token); got != "" {
		t.Fatalf("expired peer API token still resolves to %q", got)
	}
	if g.onboard.HasDevice(lease.PeerIP) {
		t.Fatal("expired peer still has device row")
	}
}
