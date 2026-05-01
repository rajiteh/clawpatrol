package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"

	utls "github.com/refraction-networking/utls"
)

// dialMTLSUpstream dials an upstream that authenticates via client
// certificate (e.g. Kubernetes API server). Loads the cert+key+CA
// from the rule's MTLS config and presents them at TLS handshake.
func dialMTLSUpstream(ctx context.Context, network, addr, serverName string, m *MTLSConfig) (net.Conn, error) {
	cert, err := tls.LoadX509KeyPair(m.Cert, m.Key)
	if err != nil {
		return nil, fmt.Errorf("mtls load cert+key: %w", err)
	}
	cfg := &tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	}
	if m.CA != "" {
		caPEM, err := os.ReadFile(m.CA)
		if err != nil {
			return nil, fmt.Errorf("mtls read ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("mtls ca: no PEM blocks parsed")
		}
		cfg.RootCAs = pool
	}
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// dialUpstreamTLS opens a TCP connection and runs stdlib TLS with
// ALPN forced to http/1.1 (our http.Transport is HTTP/1.1 only).
// Used for normal HTTP-mode upstreams.
func dialUpstreamTLS(ctx context.Context, network, addr, serverName string) (net.Conn, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{ServerName: serverName, NextProtos: []string{"http/1.1"}})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

// dialBrowserTLS opens a TCP connection and performs a uTLS handshake
// using Chrome's TLS fingerprint (HelloChrome_Auto), with ALPN forced
// to http/1.1. Used for WS upgrades to chatgpt.com — Cloudflare WAF
// otherwise rejects the WS handshake with "Attack attempt detected".
//
// Plain Go TLS works fine for chatgpt.com HTTP requests but the WS
// upgrade specifically gets fingerprint-blocked. Mimicking Chrome's
// ClientHello bypasses it.
func dialBrowserTLS(ctx context.Context, network, addr, serverName string) (net.Conn, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// HelloChrome_Auto bakes ALPN ["h2","http/1.1"] into the ClientHello.
	// We need http/1.1 only (WS upgrade requires HTTP/1.1; raw response
	// reader breaks on h2 SETTINGS frames). Apply preset spec, mutate
	// ALPNExtension, then handshake.
	c := utls.UClient(raw, &utls.Config{ServerName: serverName}, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_Auto)
	if err != nil {
		raw.Close()
		return nil, err
	}
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
	if err := c.ApplyPreset(&spec); err != nil {
		raw.Close()
		return nil, err
	}
	if err := c.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}
