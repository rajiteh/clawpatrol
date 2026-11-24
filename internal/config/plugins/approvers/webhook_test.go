package approvers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"

	_ "github.com/denoland/clawpatrol/internal/config/plugins/credentials"
)

type webhookTestCredential struct{}

func (webhookTestCredential) InjectHTTP(_ context.Context, req *http.Request, secret runtime.Secret) error {
	req.Header.Set("Authorization", "Bearer "+string(secret.Bytes))
	return nil
}

type webhookTestSecrets map[string]runtime.Secret

func (s webhookTestSecrets) Get(name string) (runtime.Secret, error) { return s[name], nil }

type webhookRoundTripFunc func(*http.Request) (*http.Response, error)

func (f webhookRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func webhookTestRequest(server *httptest.Server) (*WebhookApprover, runtime.ApproveRequest) {
	credential := &config.Entity{Body: webhookTestCredential{}}
	return &WebhookApprover{URL: server.URL, Credential: "hook", client: server.Client()}, runtime.ApproveRequest{
		ApproverName:         "access-control",
		AgentIP:              "100.64.0.12",
		PrincipalID:          "peer:100.64.0.12",
		PrincipalDisplayName: "build-agent-1",
		Profile:              "production",
		Method:               "exec",
		Host:                 "build.example.test",
		Path:                 "systemctl restart api | stdin: SECRET",
		Reason:               "sensitive action",
		Endpoint:             &config.CompiledEndpoint{Name: "build-host", Family: "ssh"},
		Rule:                 &config.CompiledRule{Name: "ssh-sensitive"},
		Policy:               &config.CompiledPolicy{Credentials: map[string]*config.Entity{"hook": credential}},
		Secrets:              webhookTestSecrets{"hook": {Bytes: []byte("test-token")}},
	}
}

func TestWebhookApproverAllowUsesExistingCredentialAndMinimalEnvelope(t *testing.T) {
	var got webhookRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("Authorization = %q", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"schema_version":1,"decision":"allow","reason":"active approval","decided_by":"raj"}`)
	}))
	defer server.Close()

	approver, req := webhookTestRequest(server)
	verdict, err := approver.Approve(t.Context(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if verdict.Decision != "allow" || verdict.Reason != "active approval" || verdict.By != "webhook:access-control:raj" {
		t.Fatalf("verdict = %#v", verdict)
	}
	if got.SchemaVersion != 1 || got.Principal.ID != "peer:100.64.0.12" || got.Principal.DisplayName != "build-agent-1" {
		t.Fatalf("principal envelope = %#v", got.Principal)
	}
	if got.Target.Family != "ssh" || got.Target.Endpoint != "build-host" || got.Policy.Rule != "ssh-sensitive" {
		t.Fatalf("request envelope = %#v", got)
	}
	if got.Action.Path != "systemctl restart api" || strings.Contains(got.Action.Path, "SECRET") {
		t.Fatalf("action path = %q; stdin preview must be excluded", got.Action.Path)
	}
}

func TestWebhookApproverFailsClosed(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantReason string
	}{
		{name: "deny", status: 200, body: `{"schema_version":1,"decision":"deny"}`, wantReason: "denied by webhook approver"},
		{name: "bad status", status: 503, body: `{}`, wantReason: "webhook approver returned HTTP 503"},
		{name: "malformed", status: 200, body: `{`, wantReason: "invalid webhook approver response"},
		{name: "unknown field", status: 200, body: `{"schema_version":1,"decision":"allow","grant":"wide"}`, wantReason: "invalid webhook approver response"},
		{name: "unknown decision", status: 200, body: `{"schema_version":1,"decision":"pending"}`, wantReason: "webhook approver returned no valid decision"},
		{name: "wrong schema", status: 200, body: `{"schema_version":2,"decision":"allow"}`, wantReason: "unsupported webhook response schema"},
		{name: "control text", status: 200, body: "{\"schema_version\":1,\"decision\":\"deny\",\"reason\":\"bad\\nlog\"}", wantReason: "invalid webhook approver response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			approver, req := webhookTestRequest(server)
			verdict, err := approver.Approve(t.Context(), req)
			if err != nil {
				t.Fatalf("Approve: %v", err)
			}
			if verdict.Decision != "deny" || verdict.Reason != tc.wantReason {
				t.Fatalf("verdict = %#v, want deny %q", verdict, tc.wantReason)
			}
		})
	}
}

func TestWebhookApproverRetriesTransientStatusOnce(t *testing.T) {
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"schema_version":1,"decision":"allow"}`)
	}))
	defer server.Close()

	approver, req := webhookTestRequest(server)
	verdict, err := approver.Approve(t.Context(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if attempts != 2 || verdict.Decision != "allow" {
		t.Fatalf("attempts = %d, verdict = %#v", attempts, verdict)
	}
}

func TestWebhookApproverRetriesTransportErrorOnce(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"schema_version":1,"decision":"allow"}`)
	}))
	defer server.Close()

	approver, req := webhookTestRequest(server)
	base := approver.client.Transport
	attempts := 0
	approver.client.Transport = webhookRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("temporary transport failure")
		}
		return base.RoundTrip(r)
	})
	approver.retryBackoff = time.Nanosecond

	verdict, err := approver.Approve(t.Context(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if attempts != 2 || verdict.Decision != "allow" {
		t.Fatalf("attempts = %d, verdict = %#v", attempts, verdict)
	}
}

func TestWebhookApproverDoesNotRetryNonTransientStatus(t *testing.T) {
	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	approver, req := webhookTestRequest(server)
	verdict, err := approver.Approve(t.Context(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if attempts != 1 || verdict.Decision != "deny" || verdict.Reason != "webhook approver returned HTTP 400" {
		t.Fatalf("attempts = %d, verdict = %#v", attempts, verdict)
	}
}

func TestWebhookApproverRejectsRedirect(t *testing.T) {
	targetCalled := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalled = true
	}))
	defer target.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer server.Close()

	approver, req := webhookTestRequest(server)
	verdict, err := approver.Approve(t.Context(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if verdict.Decision != "deny" || verdict.Reason != "webhook approver returned HTTP 302" {
		t.Fatalf("verdict = %#v", verdict)
	}
	if targetCalled {
		t.Fatal("redirect target was called")
	}
}

func TestWebhookApproverRejectsMissingSecretWithoutCallingService(t *testing.T) {
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	defer server.Close()
	approver, req := webhookTestRequest(server)
	req.Secrets = webhookTestSecrets{"hook": {}}
	verdict, err := approver.Approve(t.Context(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if verdict.Decision != "deny" || verdict.Reason != "webhook approver credential is not connected" {
		t.Fatalf("verdict = %#v", verdict)
	}
	if called {
		t.Fatal("webhook was called without credential material")
	}
}

func TestWebhookApproverCancellationFailsClosed(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() {
		close(release)
		server.Close()
	}()
	approver, req := webhookTestRequest(server)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan runtime.ApproveVerdict, 1)
	go func() {
		verdict, _ := approver.Approve(ctx, req)
		done <- verdict
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("webhook did not start")
	}
	cancel()
	select {
	case verdict := <-done:
		if verdict.Decision != "deny" || verdict.Reason != "approval canceled before decision" {
			t.Fatalf("verdict = %#v", verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("webhook did not stop after cancellation")
	}
}

func TestValidateWebhookApprover(t *testing.T) {
	for _, tc := range []struct {
		name string
		a    WebhookApprover
		ok   bool
	}{
		{name: "valid", a: WebhookApprover{URL: "https://approval.example.test/decide", Timeout: 30}, ok: true},
		{name: "http", a: WebhookApprover{URL: "http://approval.example.test/decide"}},
		{name: "query", a: WebhookApprover{URL: "https://approval.example.test/decide?token=x"}},
		{name: "userinfo", a: WebhookApprover{URL: "https://user@approval.example.test/decide"}},
		{name: "timeout", a: WebhookApprover{URL: "https://approval.example.test/decide", Timeout: 601}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diags := validateWebhookApprover(&tc.a, "test", nil)
			if got := !diags.HasErrors(); got != tc.ok {
				t.Fatalf("valid = %v, want %v: %v", got, tc.ok, diags)
			}
		})
	}
}

func TestWebhookApproverConfigRoundTrip(t *testing.T) {
	src := []byte(`
gateway {
  state_dir  = "/tmp/clawpatrol-test"
  public_url = "https://gateway.example.test"
  wireguard { subnet_cidr = "10.55.0.0/24" }
}
credential "bearer_token" "hook" {}
approver "webhook_approver" "access-control" {
  url        = "https://approval.example.test/v1/decide"
  credential = bearer_token.hook
  timeout    = 45
}
`)
	gw, diags := config.LoadBytes(src, "webhook.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	body, ok := gw.Policy.Approvers["access-control"].Body.(*WebhookApprover)
	if !ok || body.URL != "https://approval.example.test/v1/decide" || body.Credential != "hook" || body.Timeout != 45 {
		t.Fatalf("body = %#v", gw.Policy.Approvers["access-control"].Body)
	}
	emitted, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if _, diags := config.LoadBytes(emitted, "emitted.hcl"); diags.HasErrors() {
		t.Fatalf("reload emitted config: %v\n%s", diags, emitted)
	}
}
