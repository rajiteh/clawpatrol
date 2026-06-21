package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
)

const (
	dynamicPeerRegisterPath                 = "/api/dynamic-peers/register"
	dynamicPeerHeartbeatPath                = "/api/dynamic-peers/heartbeat"
	dynamicPeerTransportWireGuard           = "wireguard"
	dynamicPeerAuthorizerKubernetesTokenRev = "kubernetes_token_review"
	dynamicPeerDefaultMTU                   = 1420
)

type dynamicPeerRegisterRequest struct {
	Transport          string          `json:"transport"`
	Authorizer         string          `json:"authorizer"`
	WireGuardPublicKey string          `json:"wireguard_public_key,omitempty"`
	Claims             json.RawMessage `json:"claims,omitempty"`
}

type dynamicPeerRegisterResponse struct {
	Transport       string   `json:"transport"`
	PeerIP          string   `json:"peer_ip"`
	PeerIPv6        string   `json:"peer_ipv6"`
	ServerPublicKey string   `json:"server_public_key"`
	Endpoint        string   `json:"endpoint"`
	AllowedIPs      []string `json:"allowed_ips"`
	MTU             int      `json:"mtu"`
	LeaseTTLSeconds int      `json:"lease_ttl_seconds"`
	APIToken        string   `json:"api_token"`
	CAPEM           string   `json:"ca_pem,omitempty"`
}

type dynamicPeerIdentity struct {
	SubjectKey     string
	ReplacementKey string
	DisplayName    string
	Owner          string
	Profile        string
	Metadata       map[string]string
}

type dynamicPeerAuthorizer interface {
	Type() string
	Name() string
	Authorize(ctx context.Context, token string, claims json.RawMessage) (dynamicPeerIdentity, error)
}

type dynamicPeerTransport interface {
	Name() string
	Provision(ctx context.Context, cfg *config.Gateway, publicKeyHex, reuseIP string) (dynamicPeerTransportSession, error)
	Revoke(ctx context.Context, peerIP string)
}

type dynamicPeerTransportSession struct {
	PeerIP          string
	PeerIPv6        string
	ServerPublicKey string
	Endpoint        string
	AllowedIPs      []string
	MTU             int
}

type dynamicPeerLease struct {
	PeerIP             string
	Transport          string
	AuthorizerType     string
	AuthorizerName     string
	SubjectKey         string
	ReplacementKey     string
	DisplayName        string
	Owner              string
	Profile            string
	WireGuardPublicKey string
	MetadataJSON       string
	ExpiresNS          int64
	LastHeartbeatNS    int64
}

// dynamicPeerLeaseView is the dashboard-facing shape of a lease. Times
// are rendered for the UI's format helpers: ExpiresAt is Unix seconds
// (fmtExpiry), LastHeartbeat and CreatedAt are RFC3339 strings (fmtAge /
// fmtDateTime).
type dynamicPeerLeaseView struct {
	PeerIP         string            `json:"peer_ip"`
	Transport      string            `json:"transport"`
	AuthorizerType string            `json:"authorizer_type"`
	AuthorizerName string            `json:"authorizer_name"`
	SubjectKey     string            `json:"subject_key"`
	DisplayName    string            `json:"display_name"`
	Owner          string            `json:"owner"`
	Profile        string            `json:"profile"`
	PublicKey      string            `json:"public_key,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ExpiresAt      int64             `json:"expires_at"`
	LastHeartbeat  string            `json:"last_heartbeat"`
	CreatedAt      string            `json:"created_at"`
	Expired        bool              `json:"expired"`
}

var (
	dynamicPeerLeaseSweepInterval = 30 * time.Second
	errDynamicPeerConflict        = errors.New("dynamic peer conflict")
)

func (w *webMux) apiDynamicPeerRegister(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodDelete {
		http.Error(rw, "POST or DELETE", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodDelete {
		w.apiDynamicPeerDelete(rw, r)
		return
	}
	cfg := w.g.cfg.Load()
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		http.NotFound(rw, r)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	if token == "" {
		http.Error(rw, "missing bearer token", http.StatusUnauthorized)
		return
	}
	var req dynamicPeerRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(rw, "bad json", http.StatusBadRequest)
		return
	}
	authorizer, err := w.g.dynamicPeerAuthorizerFor(cfg, req.Transport, req.Authorizer)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	identity, err := authorizer.Authorize(r.Context(), token, req.Claims)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	if err := w.g.dynamicPeerProfileExists(identity.Profile); err != nil {
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	ttl, err := cfg.EnrollmentPeerTTL()
	if err != nil {
		http.Error(rw, "invalid lease ttl", http.StatusInternalServerError)
		return
	}
	resp, err := w.g.registerDynamicPeer(r.Context(), cfg, authorizer, &wireguardDynamicPeerTransport{}, identity, req, ttl)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errDynamicPeerConflict) {
			status = http.StatusConflict
		}
		http.Error(rw, err.Error(), status)
		return
	}
	writeJSON(rw, resp)
}

func (w *webMux) apiDynamicPeerHeartbeat(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, http.MethodPost, http.StatusMethodNotAllowed)
		return
	}
	cfg := w.g.cfg.Load()
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		http.NotFound(rw, r)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	peerIP := peerIPForAPIToken(w.g.db, token)
	if peerIP == "" {
		http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
		return
	}
	ttl, err := cfg.EnrollmentPeerTTL()
	if err != nil {
		http.Error(rw, "invalid lease ttl", http.StatusInternalServerError)
		return
	}
	lease, err := w.g.refreshDynamicPeerLease(r.Context(), peerIP, ttl)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		}
		http.Error(rw, err.Error(), status)
		return
	}
	writeJSON(rw, map[string]any{
		"transport":         lease.Transport,
		"peer_ip":           lease.PeerIP,
		"lease_ttl_seconds": int(ttl.Seconds()),
		"expires_at_ns":     lease.ExpiresNS,
	})
}

func (w *webMux) apiDynamicPeerDelete(rw http.ResponseWriter, r *http.Request) {
	cfg := w.g.cfg.Load()
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		http.NotFound(rw, r)
		return
	}
	token := bearerFromAuthHeader(r.Header.Get("Authorization"))
	peerIP := peerIPForAPIToken(w.g.db, token)
	if peerIP == "" {
		http.Error(rw, "unknown or missing peer api token", http.StatusUnauthorized)
		return
	}
	w.g.dynamicPeerMu.Lock()
	defer w.g.dynamicPeerMu.Unlock()
	// Only a peer that actually holds a dynamic-peer lease may drive this
	// teardown. A regular onboarded device can also carry a peer API token;
	// without this guard it could revoke its own WireGuard peer and forget
	// its device row by hitting the dynamic-peer delete path.
	if _, err := w.g.dynamicPeerLeaseByIP(peerIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(rw, r)
		} else {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.g.cleanupDynamicPeerLeaseByIPLocked(context.Background(), peerIP)
	rw.WriteHeader(http.StatusNoContent)
}

// apiDynamicPeerList is the dashboard read endpoint: it lists every
// dynamic-peer lease (live and not-yet-swept expired) for operator
// observability. Unlike register/heartbeat it is not gated on the
// feature flag — leases can still be draining after the feature is
// turned off, and an empty list is a fine answer when it's never been on.
func (w *webMux) apiDynamicPeerList(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, http.MethodGet, http.StatusMethodNotAllowed)
		return
	}
	views, err := w.g.listDynamicPeerLeaseViews()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, views)
}

func (g *Gateway) listDynamicPeerLeaseViews() ([]dynamicPeerLeaseView, error) {
	rows, err := g.db.Query(`
		SELECT peer_ip, transport, authorizer_type, authorizer_name, subject_key,
		       display_name, owner, profile, wireguard_public_key, metadata_json,
		       expires_ns, last_heartbeat_ns, created_ns
		FROM dynamic_peer_leases
		ORDER BY created_ns DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	nowNS := time.Now().UTC().UnixNano()
	views := []dynamicPeerLeaseView{}
	for rows.Next() {
		var (
			v           dynamicPeerLeaseView
			pubKey      sql.NullString
			metaJSON    string
			expiresNS   int64
			heartbeatNS int64
			createdNS   int64
		)
		if err := rows.Scan(&v.PeerIP, &v.Transport, &v.AuthorizerType, &v.AuthorizerName,
			&v.SubjectKey, &v.DisplayName, &v.Owner, &v.Profile, &pubKey, &metaJSON,
			&expiresNS, &heartbeatNS, &createdNS); err != nil {
			return nil, err
		}
		v.PublicKey = pubKey.String
		if metaJSON != "" && metaJSON != "{}" {
			_ = json.Unmarshal([]byte(metaJSON), &v.Metadata)
		}
		v.ExpiresAt = expiresNS / int64(time.Second)
		v.LastHeartbeat = time.Unix(0, heartbeatNS).UTC().Format(time.RFC3339Nano)
		v.CreatedAt = time.Unix(0, createdNS).UTC().Format(time.RFC3339Nano)
		v.Expired = expiresNS <= nowNS
		views = append(views, v)
	}
	return views, rows.Err()
}

func (g *Gateway) dynamicPeerAuthorizerFor(cfg *config.Gateway, transport, name string) (dynamicPeerAuthorizer, error) {
	if strings.TrimSpace(transport) != dynamicPeerTransportWireGuard {
		return nil, fmt.Errorf("unsupported dynamic peer transport %q", transport)
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("dynamic peer authorizer is required")
	}
	if cfg == nil || !cfg.IsEnrollmentEnabled() {
		return nil, fmt.Errorf("wireguard dynamic peers are not enabled")
	}
	for i := range cfg.Settings.Enrollment.Authorizers {
		a := &cfg.Settings.Enrollment.Authorizers[i]
		if a.Name != name {
			continue
		}
		switch a.Type {
		case dynamicPeerAuthorizerKubernetesTokenRev:
			return &kubernetesTokenReviewAuthorizer{
				name:     a.Name,
				cfg:      a,
				verifier: g.k8sVerifier,
			}, nil
		default:
			return nil, fmt.Errorf("unsupported dynamic peer authorizer type %q", a.Type)
		}
	}
	return nil, fmt.Errorf("dynamic peer authorizer %q is not configured", name)
}

func (g *Gateway) dynamicPeerProfileExists(profile string) error {
	if profile == "" {
		return fmt.Errorf("dynamic peer profile is empty")
	}
	policy := g.Policy()
	if policy == nil {
		return fmt.Errorf("policy not loaded")
	}
	if _, ok := policy.Profiles[profile]; !ok {
		return fmt.Errorf("profile %q is not declared", profile)
	}
	return nil
}

func (g *Gateway) registerDynamicPeer(ctx context.Context, cfg *config.Gateway, authorizer dynamicPeerAuthorizer, transport dynamicPeerTransport, identity dynamicPeerIdentity, req dynamicPeerRegisterRequest, ttl time.Duration) (dynamicPeerRegisterResponse, error) {
	pubHex, err := normalizeWGPublicKey(req.WireGuardPublicKey)
	if err != nil {
		return dynamicPeerRegisterResponse{}, err
	}
	if identity.SubjectKey == "" || identity.ReplacementKey == "" || identity.Profile == "" {
		return dynamicPeerRegisterResponse{}, fmt.Errorf("dynamic peer authorizer returned incomplete identity")
	}

	g.dynamicPeerMu.Lock()
	defer g.dynamicPeerMu.Unlock()

	now := time.Now().UTC()
	nowNS := now.UnixNano()
	expiresNS := now.Add(ttl).UnixNano()

	leases, err := g.findDynamicPeerLeases(identity.ReplacementKey, pubHex)
	if err != nil {
		return dynamicPeerRegisterResponse{}, err
	}
	var reuseIP string
	for _, lease := range leases {
		expired := lease.ExpiresNS <= nowNS
		sameSubject := lease.SubjectKey == identity.SubjectKey
		sameReplacement := lease.ReplacementKey == identity.ReplacementKey
		samePub := lease.WireGuardPublicKey == pubHex

		switch {
		case sameSubject:
			// The authenticated subject already owns a lease — typically a
			// sidecar that restarted in-place (same pod UID) with a freshly
			// generated WireGuard key. Reuse its IP and let the transport
			// install the new key (AddPeer evicts the stale pubkey on that
			// IP). Same-subject is never a conflict: the identity was just
			// re-verified by the authorizer, so it owns this slot regardless
			// of whether the key rotated or the old lease expired.
			reuseIP = lease.PeerIP
		case sameReplacement:
			// Same logical workload, different instance (e.g. a pod recreated
			// under the same name with a new UID). Retire the previous
			// instance's lease before the new one takes over.
			g.cleanupDynamicPeerLeaseByIPLocked(ctx, lease.PeerIP)
		case samePub && !expired:
			return dynamicPeerRegisterResponse{}, fmt.Errorf("%w: wireguard public key is already registered to another live dynamic peer", errDynamicPeerConflict)
		case samePub && expired:
			g.cleanupDynamicPeerLeaseByIPLocked(ctx, lease.PeerIP)
		}
	}

	session, err := transport.Provision(ctx, cfg, pubHex, reuseIP)
	if err != nil {
		return dynamicPeerRegisterResponse{}, err
	}
	// Until the lease is committed, roll back the transport + token state on
	// any failure. Otherwise a partial register leaks a wg_peers row and an
	// API token with no lease behind them, and the sweeper only reclaims IPs
	// that still have a lease row.
	committed := false
	defer func() {
		if !committed {
			transport.Revoke(ctx, session.PeerIP)
			deletePeerAPITokensForIP(g.db, session.PeerIP)
		}
	}()

	deletePeerAPITokensForIP(g.db, session.PeerIP)
	apiToken, err := mintAndPersistPeerAPIToken(g.db, session.PeerIP)
	if err != nil {
		return dynamicPeerRegisterResponse{}, err
	}

	metaJSON := "{}"
	if len(identity.Metadata) > 0 {
		meta, err := json.Marshal(identity.Metadata)
		if err != nil {
			return dynamicPeerRegisterResponse{}, err
		}
		metaJSON = string(meta)
	}
	if err := upsertDynamicPeerLease(g.db, dynamicPeerLease{
		PeerIP:             session.PeerIP,
		Transport:          transport.Name(),
		AuthorizerType:     authorizer.Type(),
		AuthorizerName:     authorizer.Name(),
		SubjectKey:         identity.SubjectKey,
		ReplacementKey:     identity.ReplacementKey,
		DisplayName:        identity.DisplayName,
		Owner:              identity.Owner,
		Profile:            identity.Profile,
		WireGuardPublicKey: pubHex,
		MetadataJSON:       metaJSON,
		ExpiresNS:          expiresNS,
		LastHeartbeatNS:    nowNS,
	}); err != nil {
		return dynamicPeerRegisterResponse{}, err
	}
	committed = true
	if g.onboard != nil {
		g.onboard.AssignProfile(session.PeerIP, identity.Profile)
		g.onboard.SetOwner(session.PeerIP, identity.Owner)
		g.onboard.SetHostname(session.PeerIP, identity.DisplayName)
	}
	if g.agents != nil {
		g.agents.Seed(session.PeerIP)
	}

	resp := dynamicPeerRegisterResponse{
		Transport:       transport.Name(),
		PeerIP:          session.PeerIP,
		PeerIPv6:        session.PeerIPv6,
		ServerPublicKey: session.ServerPublicKey,
		Endpoint:        session.Endpoint,
		AllowedIPs:      session.AllowedIPs,
		MTU:             session.MTU,
		LeaseTTLSeconds: int(ttl.Seconds()),
		APIToken:        apiToken,
	}
	if g.certs != nil {
		resp.CAPEM = string(g.certs.CertPEM())
	}
	return resp, nil
}

func (g *Gateway) refreshDynamicPeerLease(ctx context.Context, peerIP string, ttl time.Duration) (dynamicPeerLease, error) {
	g.dynamicPeerMu.Lock()
	defer g.dynamicPeerMu.Unlock()
	now := time.Now().UTC()
	expires := now.Add(ttl).UnixNano()
	res, err := g.db.Exec(
		`UPDATE dynamic_peer_leases SET expires_ns = ?, last_heartbeat_ns = ? WHERE peer_ip = ?`,
		expires, now.UnixNano(), peerIP,
	)
	if err != nil {
		return dynamicPeerLease{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return dynamicPeerLease{}, sql.ErrNoRows
	}
	lease, err := g.dynamicPeerLeaseByIP(peerIP)
	if err != nil {
		return dynamicPeerLease{}, err
	}
	if err := g.reconcileDynamicPeerLeaseLocked(ctx, lease); err != nil {
		return dynamicPeerLease{}, err
	}
	return lease, nil
}

func (g *Gateway) findDynamicPeerLeases(replacementKey, pubHex string) ([]dynamicPeerLease, error) {
	rows, err := g.db.Query(`
		SELECT peer_ip, transport, authorizer_type, authorizer_name, subject_key, replacement_key,
		       display_name, owner, profile, wireguard_public_key, metadata_json, expires_ns, last_heartbeat_ns
		FROM dynamic_peer_leases
		WHERE replacement_key = ? OR wireguard_public_key = ?
	`, replacementKey, pubHex)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []dynamicPeerLease
	for rows.Next() {
		var lease dynamicPeerLease
		if err := rows.Scan(&lease.PeerIP, &lease.Transport, &lease.AuthorizerType, &lease.AuthorizerName,
			&lease.SubjectKey, &lease.ReplacementKey, &lease.DisplayName, &lease.Owner, &lease.Profile,
			&lease.WireGuardPublicKey, &lease.MetadataJSON, &lease.ExpiresNS, &lease.LastHeartbeatNS); err != nil {
			return nil, err
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}

func (g *Gateway) dynamicPeerLeaseByIP(peerIP string) (dynamicPeerLease, error) {
	var lease dynamicPeerLease
	err := g.db.QueryRow(`
		SELECT peer_ip, transport, authorizer_type, authorizer_name, subject_key, replacement_key,
		       display_name, owner, profile, wireguard_public_key, metadata_json, expires_ns, last_heartbeat_ns
		FROM dynamic_peer_leases
		WHERE peer_ip = ?
	`, peerIP).Scan(&lease.PeerIP, &lease.Transport, &lease.AuthorizerType, &lease.AuthorizerName,
		&lease.SubjectKey, &lease.ReplacementKey, &lease.DisplayName, &lease.Owner, &lease.Profile,
		&lease.WireGuardPublicKey, &lease.MetadataJSON, &lease.ExpiresNS, &lease.LastHeartbeatNS)
	return lease, err
}

func upsertDynamicPeerLease(db *sql.DB, lease dynamicPeerLease) error {
	if lease.MetadataJSON == "" {
		lease.MetadataJSON = "{}"
	}
	_, err := db.Exec(`
		INSERT INTO dynamic_peer_leases (
			peer_ip, transport, authorizer_type, authorizer_name, subject_key, replacement_key,
			display_name, owner, profile, wireguard_public_key, metadata_json,
			expires_ns, last_heartbeat_ns, created_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(peer_ip) DO UPDATE SET
			transport = excluded.transport,
			authorizer_type = excluded.authorizer_type,
			authorizer_name = excluded.authorizer_name,
			subject_key = excluded.subject_key,
			replacement_key = excluded.replacement_key,
			display_name = excluded.display_name,
			owner = excluded.owner,
			profile = excluded.profile,
			wireguard_public_key = excluded.wireguard_public_key,
			metadata_json = excluded.metadata_json,
			expires_ns = excluded.expires_ns,
			last_heartbeat_ns = excluded.last_heartbeat_ns
	`, lease.PeerIP, lease.Transport, lease.AuthorizerType, lease.AuthorizerName, lease.SubjectKey,
		lease.ReplacementKey, lease.DisplayName, lease.Owner, lease.Profile, lease.WireGuardPublicKey,
		lease.MetadataJSON, lease.ExpiresNS, lease.LastHeartbeatNS, time.Now().UTC().UnixNano())
	return err
}

func (g *Gateway) reconcileDynamicPeerLeases(ctx context.Context) (int, error) {
	if g == nil || g.db == nil {
		return 0, nil
	}
	nowNS := time.Now().UTC().UnixNano()
	rows, err := g.db.Query(`
		SELECT peer_ip, transport, authorizer_type, authorizer_name, subject_key, replacement_key,
		       display_name, owner, profile, wireguard_public_key, metadata_json, expires_ns, last_heartbeat_ns
		FROM dynamic_peer_leases
		WHERE expires_ns > ?
		ORDER BY created_ns ASC
	`, nowNS)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var leases []dynamicPeerLease
	for rows.Next() {
		var lease dynamicPeerLease
		if err := rows.Scan(&lease.PeerIP, &lease.Transport, &lease.AuthorizerType, &lease.AuthorizerName,
			&lease.SubjectKey, &lease.ReplacementKey, &lease.DisplayName, &lease.Owner, &lease.Profile,
			&lease.WireGuardPublicKey, &lease.MetadataJSON, &lease.ExpiresNS, &lease.LastHeartbeatNS); err != nil {
			return 0, err
		}
		leases = append(leases, lease)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(leases) == 0 {
		return 0, nil
	}

	g.dynamicPeerMu.Lock()
	defer g.dynamicPeerMu.Unlock()
	var errs []error
	restored := 0
	for _, lease := range leases {
		if err := g.reconcileDynamicPeerLeaseLocked(ctx, lease); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", lease.PeerIP, err))
			continue
		}
		restored++
	}
	return restored, errors.Join(errs...)
}

func (g *Gateway) reconcileDynamicPeerLeaseLocked(_ context.Context, lease dynamicPeerLease) error {
	switch lease.Transport {
	case dynamicPeerTransportWireGuard:
		if lease.WireGuardPublicKey == "" {
			return fmt.Errorf("wireguard public key is empty")
		}
		if globalWG == nil {
			return fmt.Errorf("wireguard server not started")
		}
		if err := globalWG.AddPeer(lease.WireGuardPublicKey, lease.PeerIP); err != nil {
			return fmt.Errorf("wg add peer: %w", err)
		}
	default:
		return fmt.Errorf("unsupported dynamic peer transport %q", lease.Transport)
	}
	g.restoreDynamicPeerRegistryLocked(lease)
	return nil
}

func (g *Gateway) restoreDynamicPeerRegistryLocked(lease dynamicPeerLease) {
	if g.onboard != nil {
		g.onboard.AssignProfile(lease.PeerIP, lease.Profile)
		g.onboard.SetOwner(lease.PeerIP, lease.Owner)
		g.onboard.SetHostname(lease.PeerIP, lease.DisplayName)
	}
	if g.agents != nil {
		g.agents.Seed(lease.PeerIP)
	}
}

func (g *Gateway) cleanupDynamicPeerLeaseByIPLocked(ctx context.Context, peerIP string) {
	if peerIP == "" {
		return
	}
	lease, _ := g.dynamicPeerLeaseByIP(peerIP)
	switch lease.Transport {
	case "", dynamicPeerTransportWireGuard:
		(&wireguardDynamicPeerTransport{}).Revoke(ctx, peerIP)
	}
	deletePeerAPITokensForIP(g.db, peerIP)
	if g.onboard != nil {
		g.onboard.ForgetIP(peerIP)
	}
	if g.agents != nil {
		g.agents.Delete(peerIP)
	}
	_, _ = g.db.Exec("DELETE FROM dynamic_peer_leases WHERE peer_ip = ?", peerIP)
}

func (g *Gateway) startDynamicPeerLeaseSweeper(ctx context.Context) {
	ticker := time.NewTicker(dynamicPeerLeaseSweepInterval)
	defer ticker.Stop()
	for {
		g.sweepExpiredDynamicPeerLeases()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *Gateway) sweepExpiredDynamicPeerLeases() {
	if g == nil || g.db == nil {
		return
	}
	nowNS := time.Now().UTC().UnixNano()
	rows, err := g.db.Query("SELECT peer_ip FROM dynamic_peer_leases WHERE expires_ns <= ?", nowNS)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()
	var ips []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			ips = append(ips, ip)
		}
	}
	if err := rows.Err(); err != nil {
		return
	}
	if len(ips) == 0 {
		return
	}
	g.dynamicPeerMu.Lock()
	defer g.dynamicPeerMu.Unlock()
	for _, ip := range ips {
		g.cleanupDynamicPeerLeaseByIPLocked(context.Background(), ip)
	}
}

func (g *Gateway) logDynamicPeerReconcile(ctx context.Context) {
	restored, err := g.reconcileDynamicPeerLeases(ctx)
	if err != nil {
		log.Printf("wireguard dynamic peers: restored %d persisted lease(s) with errors: %v", restored, err)
		return
	}
	if restored > 0 {
		log.Printf("wireguard dynamic peers: restored %d persisted lease(s)", restored)
	}
}

type wireguardDynamicPeerTransport struct{}

func (t *wireguardDynamicPeerTransport) Name() string { return dynamicPeerTransportWireGuard }

func (t *wireguardDynamicPeerTransport) Provision(_ context.Context, cfg *config.Gateway, publicKeyHex, reuseIP string) (dynamicPeerTransportSession, error) {
	if globalWG == nil {
		return dynamicPeerTransportSession{}, fmt.Errorf("wireguard server not started")
	}
	peerIP := reuseIP
	var err error
	if peerIP == "" {
		peerIP, err = allocateWGPeerIP(cfg.Join())
		if err != nil {
			return dynamicPeerTransportSession{}, err
		}
	}
	if err := globalWG.AddPeer(publicKeyHex, peerIP); err != nil {
		return dynamicPeerTransportSession{}, fmt.Errorf("wg add peer: %w", err)
	}
	serverPubHex, err := globalWG.PublicKey()
	if err != nil {
		return dynamicPeerTransportSession{}, fmt.Errorf("wg server pub: %w", err)
	}
	serverPubB64, err := hexToB64(serverPubHex)
	if err != nil {
		return dynamicPeerTransportSession{}, err
	}
	endpoint, err := wgClientEndpoint(cfg.Join().WGEndpoint, cfg.PublicURL(), cfg.Join().WGListenPort)
	if err != nil {
		return dynamicPeerTransportSession{}, err
	}
	ip6 := wg6FromV4(netip.MustParseAddr(peerIP)).String()
	return dynamicPeerTransportSession{
		PeerIP:          peerIP,
		PeerIPv6:        ip6,
		ServerPublicKey: serverPubB64,
		Endpoint:        endpoint,
		AllowedIPs:      []string{"0.0.0.0/0", "::/0"},
		MTU:             dynamicPeerDefaultMTU,
	}, nil
}

func (t *wireguardDynamicPeerTransport) Revoke(_ context.Context, peerIP string) {
	if globalWG != nil {
		globalWG.RevokePeerByIP(peerIP)
	}
}

// allocateWGPeerMu serializes WireGuard /32 allocation across both the
// dashboard onboarding path (wireguardOnboarder.allocateIP) and dynamic
// peer registration, so two concurrent allocations can't read the same
// free slot from wg_peers and hand out a duplicate IP.
var allocateWGPeerMu sync.Mutex

func allocateWGPeerIP(ts JoinConfig) (string, error) {
	allocateWGPeerMu.Lock()
	defer allocateWGPeerMu.Unlock()
	used := map[string]bool{}
	if globalDB != nil {
		rows, err := globalDB.Query("SELECT ip FROM wg_peers")
		if err == nil {
			defer func() { _ = rows.Close() }()
			for rows.Next() {
				var ip string
				if rows.Scan(&ip) == nil {
					used[ip] = true
				}
			}
			if err := rows.Err(); err != nil {
				used = map[string]bool{}
			}
		}
	}
	_, cidr, err := net.ParseCIDR(ts.WGSubnetCIDR)
	if err != nil {
		return "", err
	}
	first := cidr.IP.To4()
	if first == nil {
		return "", fmt.Errorf("wireguard subnet must be IPv4")
	}
	for i := 2; i < 255; i++ {
		ip := net.IPv4(first[0], first[1], first[2], byte(i)).String()
		if !used[ip] {
			return ip, nil
		}
	}
	return "", fmt.Errorf("wireguard subnet %s exhausted", ts.WGSubnetCIDR)
}

func normalizeWGPublicKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("wireguard_public_key is required")
	}
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			return strings.ToLower(s), nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("wireguard_public_key must be a 32-byte WireGuard public key in base64 or hex")
	}
	return hex.EncodeToString(b), nil
}

type k8sDynamicPeerClaims struct {
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`
	PodUID       string `json:"pod_uid"`
	NodeName     string `json:"node_name"`
}

type k8sVerifiedPod struct {
	Namespace      string
	Name           string
	UID            string
	ServiceAccount string
	Profile        string
	NodeName       string
}

type k8sRegistrationVerifier interface {
	VerifyPod(ctx context.Context, token string, claims k8sDynamicPeerClaims, cfg *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error)
}

type kubernetesTokenReviewAuthorizer struct {
	name     string
	cfg      *config.EnrollmentAuthorizerBlock
	verifier k8sRegistrationVerifier
}

func (a *kubernetesTokenReviewAuthorizer) Type() string {
	return dynamicPeerAuthorizerKubernetesTokenRev
}
func (a *kubernetesTokenReviewAuthorizer) Name() string { return a.name }

func (a *kubernetesTokenReviewAuthorizer) Authorize(ctx context.Context, token string, claims json.RawMessage) (dynamicPeerIdentity, error) {
	var parsed k8sDynamicPeerClaims
	if len(claims) == 0 {
		return dynamicPeerIdentity{}, fmt.Errorf("claims are required")
	}
	if err := json.Unmarshal(claims, &parsed); err != nil {
		return dynamicPeerIdentity{}, fmt.Errorf("claims decode: %w", err)
	}
	if parsed.PodName == "" || parsed.PodNamespace == "" || parsed.PodUID == "" {
		return dynamicPeerIdentity{}, fmt.Errorf("pod_name, pod_namespace, and pod_uid are required")
	}
	verifier := a.verifier
	if verifier == nil {
		v, err := newInClusterK8sClient()
		if err != nil {
			return dynamicPeerIdentity{}, err
		}
		verifier = v
	}
	pod, err := verifier.VerifyPod(ctx, token, parsed, a.cfg)
	if err != nil {
		return dynamicPeerIdentity{}, err
	}
	displayName := pod.Namespace + "/" + pod.Name
	owner := "system:serviceaccount:" + pod.Namespace + ":" + pod.ServiceAccount
	return dynamicPeerIdentity{
		SubjectKey:     "kubernetes:" + pod.Namespace + ":" + pod.UID,
		ReplacementKey: "kubernetes:" + pod.Namespace + ":" + pod.Name,
		DisplayName:    displayName,
		Owner:          owner,
		Profile:        pod.Profile,
		Metadata: map[string]string{
			"pod_namespace":   pod.Namespace,
			"pod_name":        pod.Name,
			"pod_uid":         pod.UID,
			"service_account": pod.ServiceAccount,
			"node_name":       pod.NodeName,
		},
	}, nil
}

type inClusterK8sClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func newInClusterK8sClient() (*inClusterK8sClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("kubernetes service environment is not available")
	}
	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read gateway serviceaccount token: %w", err)
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"); err == nil {
		roots.AppendCertsFromPEM(ca)
	}
	return &inClusterK8sClient{
		baseURL: "https://" + net.JoinHostPort(host, port),
		token:   strings.TrimSpace(string(token)),
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots},
			},
		},
	}, nil
}

func (c *inClusterK8sClient) VerifyPod(ctx context.Context, token string, claims k8sDynamicPeerClaims, cfg *config.EnrollmentAuthorizerBlock) (k8sVerifiedPod, error) {
	user, err := c.tokenReview(ctx, token, cfg.Audience)
	if err != nil {
		return k8sVerifiedPod{}, err
	}
	ns, sa, ok := serviceAccountFromUsername(user.Username)
	if !ok {
		return k8sVerifiedPod{}, fmt.Errorf("token is not a serviceaccount token")
	}
	if ns != claims.PodNamespace {
		return k8sVerifiedPod{}, fmt.Errorf("token namespace does not match pod_namespace")
	}
	pod, err := c.getPod(ctx, claims.PodNamespace, claims.PodName)
	if err != nil {
		return k8sVerifiedPod{}, err
	}
	if pod.UID != claims.PodUID {
		return k8sVerifiedPod{}, fmt.Errorf("pod UID mismatch")
	}
	if pod.ServiceAccountName != sa {
		return k8sVerifiedPod{}, fmt.Errorf("token serviceaccount does not match pod serviceaccount")
	}
	profile := strings.TrimSpace(pod.Labels[cfg.ProfileLabel])
	if profile == "" {
		return k8sVerifiedPod{}, fmt.Errorf("pod is missing profile label %q", cfg.ProfileLabel)
	}
	if !k8sRegistrationAllowed(cfg, ns, sa, profile) {
		return k8sVerifiedPod{}, fmt.Errorf("namespace/serviceaccount/profile is not allowed")
	}
	return k8sVerifiedPod{
		Namespace:      claims.PodNamespace,
		Name:           claims.PodName,
		UID:            claims.PodUID,
		ServiceAccount: sa,
		Profile:        profile,
		NodeName:       pod.NodeName,
	}, nil
}

type tokenReviewUser struct {
	Username string
}

func (c *inClusterK8sClient) tokenReview(ctx context.Context, podToken, audience string) (tokenReviewUser, error) {
	body := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec": map[string]any{
			"token":     podToken,
			"audiences": []string{audience},
		},
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return tokenReviewUser{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/apis/authentication.k8s.io/v1/tokenreviews", &buf)
	if err != nil {
		return tokenReviewUser{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return tokenReviewUser{}, fmt.Errorf("tokenreview: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return tokenReviewUser{}, fmt.Errorf("tokenreview status %d", resp.StatusCode)
	}
	var out struct {
		Status struct {
			Authenticated bool `json:"authenticated"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
			Error string `json:"error"`
		} `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return tokenReviewUser{}, fmt.Errorf("tokenreview decode: %w", err)
	}
	if !out.Status.Authenticated {
		if out.Status.Error != "" {
			return tokenReviewUser{}, fmt.Errorf("tokenreview rejected token: %s", out.Status.Error)
		}
		return tokenReviewUser{}, fmt.Errorf("tokenreview rejected token")
	}
	return tokenReviewUser{Username: out.Status.User.Username}, nil
}

type k8sPodInfo struct {
	UID                string
	Labels             map[string]string
	ServiceAccountName string
	NodeName           string
}

func (c *inClusterK8sClient) getPod(ctx context.Context, namespace, name string) (k8sPodInfo, error) {
	url := c.baseURL + "/api/v1/namespaces/" + pathEscape(namespace) + "/pods/" + pathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return k8sPodInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return k8sPodInfo{}, fmt.Errorf("get pod: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return k8sPodInfo{}, fmt.Errorf("pod not found")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return k8sPodInfo{}, fmt.Errorf("get pod status %d", resp.StatusCode)
	}
	var out struct {
		Metadata struct {
			UID    string            `json:"uid"`
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			ServiceAccountName string `json:"serviceAccountName"`
			NodeName           string `json:"nodeName"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return k8sPodInfo{}, fmt.Errorf("pod decode: %w", err)
	}
	return k8sPodInfo{
		UID:                out.Metadata.UID,
		Labels:             out.Metadata.Labels,
		ServiceAccountName: out.Spec.ServiceAccountName,
		NodeName:           out.Spec.NodeName,
	}, nil
}

func pathEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%", "%25"), "/", "%2F")
}

func serviceAccountFromUsername(username string) (namespace, serviceAccount string, ok bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(username, prefix)
	parts := strings.Split(rest, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func k8sRegistrationAllowed(cfg *config.EnrollmentAuthorizerBlock, namespace, serviceAccount, profile string) bool {
	for _, rule := range cfg.Allow {
		if rule.Namespace == namespace &&
			rule.ServiceAccount == serviceAccount &&
			slices.Contains(rule.Profiles, profile) {
			return true
		}
	}
	return false
}
