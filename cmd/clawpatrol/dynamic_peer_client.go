package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Dynamic-peer client core — transport-agnostic. These calls (register /
// fetch env / heartbeat / deregister) and the claims providers are
// independent of how traffic is actually carried, so they're shared by
// `run --tun` (TUN transport) and, in future, the unprivileged gVisor
// transport. The transport-specific bring-up lives elsewhere.

func dynamicPeerRegister(ctx context.Context, gatewayURL, token string, reqBody dynamicPeerRegisterRequest) (dynamicPeerRegisterResponse, error) {
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

func dynamicPeerFetchEnv(ctx context.Context, gatewayURL, apiToken string) ([]pushdownEnvVar, error) {
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

func dynamicPeerHeartbeatLoop(ctx context.Context, gatewayURL, apiToken string, ttlSeconds int) {
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

func dynamicPeerDeregister(ctx context.Context, gatewayURL, apiToken string) {
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

// gatherDynamicPeerClaims dispatches on the authorizer type — mirroring
// the gateway's `authorizer "<type>" "<name>"` block — to the matching
// client claims provider. Returns the JSON claims plus the credential to
// present on the wire. v1 ships one provider.
func gatherDynamicPeerClaims(authorizerType, kubeTokenPath string) (json.RawMessage, string, error) {
	switch authorizerType {
	case dynamicPeerAuthorizerKubernetesTokenRev:
		return kubernetesProviderClaims(kubeTokenPath)
	default:
		return nil, "", fmt.Errorf("unsupported dynamic peer authorizer type %q", authorizerType)
	}
}

// kubernetesProviderClaims gathers the kubernetes_token_review identity:
// claims from the downward-API POD_* env, credential from the projected
// ServiceAccount token.
func kubernetesProviderClaims(kubeTokenPath string) (json.RawMessage, string, error) {
	podName := os.Getenv("POD_NAME")
	podNamespace := os.Getenv("POD_NAMESPACE")
	podUID := os.Getenv("POD_UID")
	nodeName := os.Getenv("NODE_NAME")
	if podName == "" || podNamespace == "" || podUID == "" {
		return nil, "", fmt.Errorf("POD_NAME, POD_NAMESPACE, and POD_UID must be supplied by the Downward API")
	}
	tokenBytes, err := os.ReadFile(kubeTokenPath)
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
