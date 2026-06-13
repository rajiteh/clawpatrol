package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

// keyA and keyB are distinct, well-formed 32-byte WireGuard public keys
// rendered as 64-char hex (what normalizeWGPublicKey returns).
const (
	keyA = "abababababababababababababababababababababababababababababababab"
	keyB = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

func newDynamicPeerTestGateway(t *testing.T) *Gateway {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	g := &Gateway{db: db, onboard: newOnboardRegistry(), agents: NewAgentRegistry()}
	if err := g.onboard.Load(db); err != nil {
		t.Fatalf("onboard load: %v", err)
	}
	return g
}

// fakeDynamicPeerTransport records provisions/revokes and hands out a
// fixed IP when the caller does not pass a reuse IP.
type fakeDynamicPeerTransport struct {
	allocIP        string
	provisionErr   error
	provisionCalls int
	lastReuseIP    string
	revoked        []string
}

func (f *fakeDynamicPeerTransport) Name() string { return dynamicPeerTransportWireGuard }

func (f *fakeDynamicPeerTransport) Provision(_ context.Context, _ *config.Gateway, _, reuseIP string) (dynamicPeerTransportSession, error) {
	f.provisionCalls++
	f.lastReuseIP = reuseIP
	if f.provisionErr != nil {
		return dynamicPeerTransportSession{}, f.provisionErr
	}
	ip := reuseIP
	if ip == "" {
		ip = f.allocIP
	}
	return dynamicPeerTransportSession{
		PeerIP:          ip,
		PeerIPv6:        "fd77::1",
		ServerPublicKey: "srv-pub",
		Endpoint:        "ep.example:51820",
		AllowedIPs:      []string{"0.0.0.0/0", "::/0"},
		MTU:             dynamicPeerDefaultMTU,
	}, nil
}

func (f *fakeDynamicPeerTransport) Revoke(_ context.Context, ip string) {
	f.revoked = append(f.revoked, ip)
}

type fakeDynamicPeerAuthorizer struct{ typ, name string }

func (f fakeDynamicPeerAuthorizer) Type() string { return f.typ }
func (f fakeDynamicPeerAuthorizer) Name() string { return f.name }
func (f fakeDynamicPeerAuthorizer) Authorize(context.Context, string, json.RawMessage) (dynamicPeerIdentity, error) {
	return dynamicPeerIdentity{}, nil
}

func registerFor(t *testing.T, g *Gateway, tr dynamicPeerTransport, subjectKey, replacementKey, pub string) (dynamicPeerRegisterResponse, error) {
	t.Helper()
	id := dynamicPeerIdentity{
		SubjectKey:     subjectKey,
		ReplacementKey: replacementKey,
		DisplayName:    "agents/x",
		Owner:          "system:serviceaccount:agents:agent-runner",
		Profile:        "default",
		Metadata:       map[string]string{"subject": subjectKey},
	}
	auth := fakeDynamicPeerAuthorizer{typ: dynamicPeerAuthorizerKubernetesTokenRev, name: "agents"}
	return g.registerDynamicPeer(context.Background(), nil, auth, tr, id, dynamicPeerRegisterRequest{WireGuardPublicKey: pub}, 2*time.Minute)
}

func seedLease(t *testing.T, g *Gateway, ip, subject, replacement, pub string, expires time.Time) {
	t.Helper()
	if err := upsertDynamicPeerLease(g.db, dynamicPeerLease{
		PeerIP:             ip,
		Transport:          dynamicPeerTransportWireGuard,
		AuthorizerType:     dynamicPeerAuthorizerKubernetesTokenRev,
		AuthorizerName:     "agents",
		SubjectKey:         subject,
		ReplacementKey:     replacement,
		DisplayName:        "agents/x",
		Owner:              "system:serviceaccount:agents:agent-runner",
		Profile:            "default",
		WireGuardPublicKey: pub,
		MetadataJSON:       "{}",
		ExpiresNS:          expires.UnixNano(),
		LastHeartbeatNS:    time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

func TestRegisterDynamicPeerFresh(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.2"}
	resp, err := registerFor(t, g, tr, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP != "10.55.0.2" {
		t.Fatalf("peer_ip = %q, want 10.55.0.2", resp.PeerIP)
	}
	if resp.APIToken == "" || resp.Transport != dynamicPeerTransportWireGuard {
		t.Fatalf("unexpected response %+v", resp)
	}
	if resp.LeaseTTLSeconds != 120 {
		t.Fatalf("lease_ttl_seconds = %d, want 120", resp.LeaseTTLSeconds)
	}
	lease, err := g.dynamicPeerLeaseByIP("10.55.0.2")
	if err != nil {
		t.Fatalf("lease not persisted: %v", err)
	}
	if lease.WireGuardPublicKey != keyA {
		t.Fatalf("lease pubkey = %q, want %q", lease.WireGuardPublicKey, keyA)
	}
	if peerIPForAPIToken(g.db, resp.APIToken) != "10.55.0.2" {
		t.Fatal("api token does not resolve to peer ip")
	}
}

func TestRegisterDynamicPeerSameSubjectReusesIP(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	seedLease(t, g, "10.55.0.2", "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA, time.Now().Add(time.Minute))
	// allocIP differs from the existing lease IP so a reuse miss is visible.
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.99"}
	resp, err := registerFor(t, g, tr, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP != "10.55.0.2" {
		t.Fatalf("peer_ip = %q, want reuse of 10.55.0.2", resp.PeerIP)
	}
	if tr.lastReuseIP != "10.55.0.2" {
		t.Fatalf("transport reuseIP = %q, want 10.55.0.2", tr.lastReuseIP)
	}
}

// A sidecar that restarts in place keeps its pod UID but generates a fresh
// WireGuard key. The same subject must be allowed to take over its own slot
// (reuse the IP, swap the key) instead of being locked out until the old
// lease expires.
func TestRegisterDynamicPeerSameSubjectNewKey(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	seedLease(t, g, "10.55.0.2", "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA, time.Now().Add(time.Minute))
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.99"}
	resp, err := registerFor(t, g, tr, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyB)
	if err != nil {
		t.Fatalf("same-subject key rotation should not conflict: %v", err)
	}
	if resp.PeerIP != "10.55.0.2" {
		t.Fatalf("peer_ip = %q, want reuse of 10.55.0.2", resp.PeerIP)
	}
	lease, err := g.dynamicPeerLeaseByIP("10.55.0.2")
	if err != nil {
		t.Fatalf("lease lookup: %v", err)
	}
	if lease.WireGuardPublicKey != keyB {
		t.Fatalf("lease pubkey = %q, want rotated key %q", lease.WireGuardPublicKey, keyB)
	}
}

// A different subject presenting a live peer's public key is a conflict.
func TestRegisterDynamicPeerPublicKeyConflict(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	seedLease(t, g, "10.55.0.2", "kubernetes:agents:uid-other", "kubernetes:agents:other-pod", keyA, time.Now().Add(time.Minute))
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.3"}
	_, err := registerFor(t, g, tr, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if !errors.Is(err, errDynamicPeerConflict) {
		t.Fatalf("err = %v, want conflict", err)
	}
}

// A pod recreated under the same name (new UID) retires the prior instance's
// lease and gets a fresh IP.
func TestRegisterDynamicPeerReplacementTakeover(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	seedLease(t, g, "10.55.0.5", "kubernetes:agents:uid-old", "kubernetes:agents:agent-1", keyA, time.Now().Add(time.Minute))
	oldToken, err := mintAndPersistPeerAPIToken(g.db, "10.55.0.5")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.6"}
	resp, err := registerFor(t, g, tr, "kubernetes:agents:uid-new", "kubernetes:agents:agent-1", keyB)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP != "10.55.0.6" {
		t.Fatalf("peer_ip = %q, want fresh 10.55.0.6", resp.PeerIP)
	}
	if _, err := g.dynamicPeerLeaseByIP("10.55.0.5"); err == nil {
		t.Fatal("old instance lease should have been retired")
	}
	if peerIPForAPIToken(g.db, oldToken) != "" {
		t.Fatal("old instance api token should have been revoked")
	}
}

// An expired lease holding the requested key is reclaimed, not a conflict.
func TestRegisterDynamicPeerExpiredPublicKeyReclaimed(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	seedLease(t, g, "10.55.0.8", "kubernetes:agents:uid-old", "kubernetes:agents:old-pod", keyA, time.Now().Add(-time.Minute))
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.9"}
	resp, err := registerFor(t, g, tr, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP != "10.55.0.9" {
		t.Fatalf("peer_ip = %q, want fresh 10.55.0.9", resp.PeerIP)
	}
	if _, err := g.dynamicPeerLeaseByIP("10.55.0.8"); err == nil {
		t.Fatal("expired lease should have been reclaimed")
	}
}

// When persistence fails after the transport has provisioned, the register
// path must roll back the transport peer + API token so nothing leaks.
func TestRegisterDynamicPeerRollbackOnPersistFailure(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	// Drop the token table so mintAndPersistPeerAPIToken fails after the
	// fake transport has already provisioned.
	if _, err := g.db.Exec("DROP TABLE peer_api_tokens"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	tr := &fakeDynamicPeerTransport{allocIP: "10.55.0.2"}
	if _, err := registerFor(t, g, tr, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA); err == nil {
		t.Fatal("expected register to fail")
	}
	if len(tr.revoked) != 1 || tr.revoked[0] != "10.55.0.2" {
		t.Fatalf("transport revoked = %v, want rollback of 10.55.0.2", tr.revoked)
	}
	if _, err := g.dynamicPeerLeaseByIP("10.55.0.2"); err == nil {
		t.Fatal("no lease should be persisted on failure")
	}
}

func TestApiDynamicPeerList(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	w := &webMux{g: g}

	seedLease(t, g, "10.55.0.2", "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA, time.Now().Add(time.Minute))
	seedLease(t, g, "10.55.0.3", "kubernetes:agents:uid-2", "kubernetes:agents:agent-2", keyB, time.Now().Add(-time.Minute))

	postRec := httptest.NewRecorder()
	w.apiDynamicPeerList(postRec, httptest.NewRequest(http.MethodPost, "/api/dynamic-peers", nil))
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST -> %d, want 405", postRec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/dynamic-peers", nil)
	rec := httptest.NewRecorder()
	w.apiDynamicPeerList(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET -> %d, want 200", rec.Code)
	}
	var views []dynamicPeerLeaseView
	if err := json.NewDecoder(rec.Body).Decode(&views); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("want 2 leases, got %d", len(views))
	}
	byIP := map[string]dynamicPeerLeaseView{}
	for _, v := range views {
		byIP[v.PeerIP] = v
	}
	live := byIP["10.55.0.2"]
	if live.Profile != "default" || live.Expired || live.PublicKey != keyA {
		t.Fatalf("unexpected live lease view %+v", live)
	}
	if live.DisplayName != "agents/x" || live.AuthorizerType != dynamicPeerAuthorizerKubernetesTokenRev {
		t.Fatalf("unexpected lease metadata %+v", live)
	}
	if live.ExpiresAt == 0 || live.CreatedAt == "" || live.LastHeartbeat == "" {
		t.Fatalf("missing timestamps %+v", live)
	}
	if !byIP["10.55.0.3"].Expired {
		t.Fatal("expected expired flag for 10.55.0.3")
	}
}

func enabledDynamicPeersCfg() *config.Gateway {
	return &config.Gateway{Settings: &config.GatewaySettings{
		WireGuard: &config.WireGuardBlock{
			DynamicPeers: &config.DynamicPeersBlock{
				Enabled: true,
				Authorizers: []config.DynamicPeerAuthorizerBlock{{
					Type:         dynamicPeerAuthorizerKubernetesTokenRev,
					Name:         "agents",
					Audience:     "clawpatrol",
					ProfileLabel: "clawpatrol.dev/profile",
					Allow: []config.DynamicPeerKubernetesAllow{{
						Namespace:      "agents",
						ServiceAccount: "agent-runner",
						Profiles:       []string{"default"},
					}},
				}},
			},
		},
	}}
}

func doRegister(w *webMux, method, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, dynamicPeerRegisterPath, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	w.apiDynamicPeerRegister(rec, req)
	return rec
}

func TestApiDynamicPeerRegisterGuards(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	g.cfg.Store(enabledDynamicPeersCfg())
	g.policy.Store(&config.CompiledPolicy{Profiles: map[string]*config.CompiledProfile{"default": {}}})
	// Verifier resolves any token to a pod in the "ghost" profile, which is
	// not declared in the policy above.
	g.k8sVerifier = fakeK8sVerifier(func(_ context.Context, _ string, claims k8sDynamicPeerClaims, _ *config.DynamicPeerAuthorizerBlock) (k8sVerifiedPod, error) {
		return k8sVerifiedPod{
			Namespace:      claims.PodNamespace,
			Name:           claims.PodName,
			UID:            claims.PodUID,
			ServiceAccount: "agent-runner",
			Profile:        "ghost",
		}, nil
	})
	w := &webMux{g: g}

	validBody := `{"transport":"wireguard","authorizer":"agents","wireguard_public_key":"` + keyA + `","claims":{"pod_name":"a","pod_namespace":"agents","pod_uid":"u"}}`

	if rec := doRegister(w, http.MethodGet, "tok", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET -> %d, want 405", rec.Code)
	}
	if rec := doRegister(w, http.MethodPost, "", validBody); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing bearer -> %d, want 401", rec.Code)
	}
	if rec := doRegister(w, http.MethodPost, "tok", "{not json"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json -> %d, want 400", rec.Code)
	}
	unknownAuthz := `{"transport":"wireguard","authorizer":"nope","wireguard_public_key":"` + keyA + `","claims":{"pod_name":"a","pod_namespace":"agents","pod_uid":"u"}}`
	if rec := doRegister(w, http.MethodPost, "tok", unknownAuthz); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown authorizer -> %d, want 403", rec.Code)
	}
	badTransport := `{"transport":"carrier-pigeon","authorizer":"agents","claims":{}}`
	if rec := doRegister(w, http.MethodPost, "tok", badTransport); rec.Code != http.StatusForbidden {
		t.Fatalf("bad transport -> %d, want 403", rec.Code)
	}
	// Authorize succeeds but the resolved profile is not declared.
	if rec := doRegister(w, http.MethodPost, "tok", validBody); rec.Code != http.StatusForbidden {
		t.Fatalf("undeclared profile -> %d, want 403", rec.Code)
	}

	// Disabled feature hides the endpoint entirely.
	g.cfg.Store(&config.Gateway{Settings: &config.GatewaySettings{WireGuard: &config.WireGuardBlock{}}})
	if rec := doRegister(w, http.MethodPost, "tok", validBody); rec.Code != http.StatusNotFound {
		t.Fatalf("disabled -> %d, want 404", rec.Code)
	}
}

// A regular onboarded peer carrying a peer API token must not be able to drive
// the dynamic-peer delete teardown when it holds no dynamic lease.
func TestApiDynamicPeerDeleteRequiresLease(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	g.cfg.Store(enabledDynamicPeersCfg())
	w := &webMux{g: g}

	const ip = "10.55.0.50"
	g.onboard.AssignProfile(ip, "default")
	g.onboard.SetHostname(ip, "regular-device")
	token, err := mintAndPersistPeerAPIToken(g.db, ip)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, dynamicPeerRegisterPath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	w.apiDynamicPeerRegister(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete without lease -> %d, want 404", rec.Code)
	}
	if peerIPForAPIToken(g.db, token) != ip {
		t.Fatal("regular peer api token was wrongly revoked")
	}
	if !g.onboard.HasDevice(ip) {
		t.Fatal("regular peer device row was wrongly forgotten")
	}
}

func TestApiDynamicPeerDeleteWithLease(t *testing.T) {
	g := newDynamicPeerTestGateway(t)
	g.cfg.Store(enabledDynamicPeersCfg())
	w := &webMux{g: g}

	const ip = "10.55.0.60"
	seedLease(t, g, ip, "kubernetes:agents:uid-1", "kubernetes:agents:agent-1", keyA, time.Now().Add(time.Minute))
	g.onboard.AssignProfile(ip, "default")
	g.onboard.SetHostname(ip, "agents/agent-1")
	token, err := mintAndPersistPeerAPIToken(g.db, ip)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, dynamicPeerRegisterPath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	w.apiDynamicPeerRegister(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete with lease -> %d, want 204", rec.Code)
	}
	if _, err := g.dynamicPeerLeaseByIP(ip); err == nil {
		t.Fatal("lease should be gone after delete")
	}
	if peerIPForAPIToken(g.db, token) != "" {
		t.Fatal("api token should be revoked after delete")
	}
	if g.onboard.HasDevice(ip) {
		t.Fatal("device row should be forgotten after delete")
	}
}
