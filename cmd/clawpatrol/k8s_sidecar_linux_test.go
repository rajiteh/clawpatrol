//go:build linux

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestK8sSidecarRegisterRequest(t *testing.T) {
	var gotAuth, gotContentType string
	var gotBody dynamicPeerRegisterRequest
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(rw).Encode(dynamicPeerRegisterResponse{
			Transport:       dynamicPeerTransportWireGuard,
			PeerIP:          "10.55.0.2",
			ServerPublicKey: "srv-pub",
			Endpoint:        "ep.example:51820",
			APIToken:        "peer-token",
			LeaseTTLSeconds: 120,
		})
	}))
	defer srv.Close()

	claims, err := json.Marshal(k8sDynamicPeerClaims{
		PodName:      "agent-1",
		PodNamespace: "agents",
		PodUID:       "uid-1",
		NodeName:     "kind-worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := k8sSidecarRegister(context.Background(), srv.URL+"/", "sa-token", dynamicPeerRegisterRequest{
		Transport:          dynamicPeerTransportWireGuard,
		Authorizer:         "agents",
		WireGuardPublicKey: keyA,
		Claims:             claims,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.PeerIP != "10.55.0.2" || resp.APIToken != "peer-token" {
		t.Fatalf("unexpected response %+v", resp)
	}
	if gotAuth != "Bearer sa-token" {
		t.Fatalf("Authorization = %q, want Bearer sa-token", gotAuth)
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q", gotContentType)
	}
	if gotBody.Transport != dynamicPeerTransportWireGuard || gotBody.Authorizer != "agents" || gotBody.WireGuardPublicKey != keyA {
		t.Fatalf("unexpected request body %+v", gotBody)
	}
	var gotClaims k8sDynamicPeerClaims
	if err := json.Unmarshal(gotBody.Claims, &gotClaims); err != nil {
		t.Fatalf("claims decode: %v", err)
	}
	if gotClaims.PodUID != "uid-1" || gotClaims.PodNamespace != "agents" || gotClaims.PodName != "agent-1" || gotClaims.NodeName != "kind-worker" {
		t.Fatalf("claims = %+v", gotClaims)
	}
}

func TestK8sSidecarRegisterRejectsErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		http.Error(rw, "namespace/serviceaccount/profile is not allowed", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := k8sSidecarRegister(context.Background(), srv.URL, "sa-token", dynamicPeerRegisterRequest{
		Transport: dynamicPeerTransportWireGuard, Authorizer: "agents", WireGuardPublicKey: keyA,
	}); err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestK8sSidecarRegisterRejectsIncompleteResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		// Valid transport but missing peer_ip / server_public_key / token.
		_ = json.NewEncoder(rw).Encode(dynamicPeerRegisterResponse{
			Transport:       dynamicPeerTransportWireGuard,
			LeaseTTLSeconds: 120,
		})
	}))
	defer srv.Close()
	if _, err := k8sSidecarRegister(context.Background(), srv.URL, "sa-token", dynamicPeerRegisterRequest{
		Transport: dynamicPeerTransportWireGuard, Authorizer: "agents", WireGuardPublicKey: keyA,
	}); err == nil {
		t.Fatal("expected error for incomplete response")
	}
}
