package approvers

// webhook_approver: synchronously asks an operator-owned HTTPS service for
// an allow or deny decision. This first version uses the existing HTTP
// credential interface for request authentication and TLS for the response
// trust boundary. It intentionally sends no request body or secret values.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const (
	webhookDefaultTimeout = 30 * time.Second
	webhookMaxTimeout     = 600 * time.Second
	webhookMaxResponse    = 64 << 10
	webhookRetryBackoff   = 500 * time.Millisecond
	webhookMaxAttempts    = 2
)

// WebhookApprover calls an external synchronous decision service.
type WebhookApprover struct {
	// URL is the absolute HTTPS decision endpoint.
	URL string `hcl:"url"`
	// Credential authenticates the request through an existing HTTP
	// credential plugin, such as bearer_token or header_token.
	Credential string `hcl:"credential"`
	// Timeout is the overall decision timeout in seconds.
	Timeout int `hcl:"timeout,optional"`

	client       *http.Client
	retryBackoff time.Duration
}

type webhookRequest struct {
	SchemaVersion int              `json:"schema_version"`
	Approver      string           `json:"approver"`
	Principal     webhookPrincipal `json:"principal"`
	Policy        webhookPolicy    `json:"policy"`
	Target        webhookTarget    `json:"target"`
	Action        webhookAction    `json:"action"`
}

type webhookPrincipal struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name,omitempty"`
	AgentIP     string `json:"agent_ip"`
	Profile     string `json:"profile"`
}

type webhookPolicy struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason,omitempty"`
}

type webhookTarget struct {
	Endpoint string `json:"endpoint"`
	Family   string `json:"family"`
	Host     string `json:"host"`
}

type webhookAction struct {
	Method    string `json:"method"`
	Path      string `json:"path,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type webhookResponse struct {
	SchemaVersion int    `json:"schema_version"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason,omitempty"`
	DecidedBy     string `json:"decided_by,omitempty"`
}

// Approve implements runtime.ApproverRuntime.
func (a *WebhookApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateWebhookURL(a.URL); err != nil {
		return webhookDeny("webhook approver configuration is invalid"), nil
	}
	if req.Policy == nil || req.Secrets == nil || a.Credential == "" {
		return webhookDeny("webhook approver credential is not connected"), nil
	}
	cred, ok := req.Policy.Credentials[a.Credential]
	if !ok {
		return webhookDeny("webhook approver credential is not connected"), nil
	}
	injector, ok := cred.Body.(runtime.HTTPCredentialRuntime)
	if !ok {
		return webhookDeny("webhook approver credential is incompatible"), nil
	}

	body, err := json.Marshal(buildWebhookRequest(req))
	if err != nil {
		return webhookDeny("webhook approver request is invalid"), nil
	}
	callCtx, cancel := context.WithTimeout(ctx, a.timeout())
	defer cancel()
	secret, err := req.Secrets.Get(a.Credential)
	if err != nil {
		return webhookDeny("webhook approver credential is not connected"), nil
	}
	if !webhookSecretPresent(secret) {
		return webhookDeny("webhook approver credential is not connected"), nil
	}
	client := a.httpClient()
	var resp *http.Response
	for attempt := 1; attempt <= webhookMaxAttempts; attempt++ {
		hreq, requestErr := http.NewRequestWithContext(callCtx, http.MethodPost, a.URL, bytes.NewReader(body))
		if requestErr != nil {
			return webhookDeny("webhook approver configuration is invalid"), nil
		}
		hreq.Header.Set("Content-Type", "application/json")
		hreq.Header.Set("Accept", "application/json")
		hreq.Header.Set("User-Agent", "clawpatrol-webhook-approver/1")
		if requestErr = injector.InjectHTTP(callCtx, hreq, secret); requestErr != nil {
			discardHTTPRedactions(injector, hreq)
			return webhookDeny("webhook approver credential is invalid"), nil
		}
		discardHTTPRedactions(injector, hreq)

		resp, err = client.Do(hreq)
		if attempt == webhookMaxAttempts || !webhookShouldRetry(resp, err) {
			break
		}
		delay := a.retryDelay(resp)
		closeWebhookResponse(resp)
		resp = nil
		if waitErr := webhookWaitForRetry(callCtx, delay); waitErr != nil {
			err = waitErr
			break
		}
	}
	if err != nil {
		closeWebhookResponse(resp)
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			return webhookDeny("approval canceled before decision"), nil
		case errors.Is(callCtx.Err(), context.DeadlineExceeded):
			return webhookDeny("webhook approver timed out"), nil
		default:
			return webhookDeny("webhook approver unavailable"), nil
		}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return webhookDeny(fmt.Sprintf("webhook approver returned HTTP %d", resp.StatusCode)), nil
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, webhookMaxResponse+1))
	if err != nil {
		return webhookDeny("invalid webhook approver response"), nil
	}
	if len(raw) > webhookMaxResponse {
		return webhookDeny("webhook approver response exceeded limit"), nil
	}
	var result webhookResponse
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return webhookDeny("invalid webhook approver response"), nil
	}
	if err := requireJSONEOF(dec); err != nil {
		return webhookDeny("invalid webhook approver response"), nil
	}
	if result.SchemaVersion != 1 {
		return webhookDeny("unsupported webhook response schema"), nil
	}
	if !safeWebhookText(result.Reason, 4096) || !safeWebhookText(result.DecidedBy, 256) {
		return webhookDeny("invalid webhook approver response"), nil
	}
	if result.Decision != "allow" && result.Decision != "deny" {
		return webhookDeny("webhook approver returned no valid decision"), nil
	}

	reason := strings.TrimSpace(result.Reason)
	if reason == "" {
		reason = "approved by webhook approver"
		if result.Decision == "deny" {
			reason = "denied by webhook approver"
		}
	}
	by := "webhook:" + req.ApproverName
	if decidedBy := strings.TrimSpace(result.DecidedBy); decidedBy != "" {
		by += ":" + decidedBy
	}
	return runtime.ApproveVerdict{Decision: result.Decision, Reason: reason, By: by}, nil
}

func webhookShouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	return resp != nil && (resp.StatusCode == http.StatusTooManyRequests ||
		(resp.StatusCode >= 500 && resp.StatusCode < 600))
}

func (a *WebhookApprover) retryDelay(resp *http.Response) time.Duration {
	if resp != nil {
		if value := strings.TrimSpace(resp.Header.Get("Retry-After")); value != "" {
			if when, err := http.ParseTime(value); err == nil {
				if delay := time.Until(when); delay > 0 {
					return delay
				}
				return 0
			}
			if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	if a.retryBackoff > 0 {
		return a.retryBackoff
	}
	return webhookRetryBackoff
}

func closeWebhookResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_ = resp.Body.Close()
}

func webhookWaitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func webhookSecretPresent(secret runtime.Secret) bool {
	if len(secret.Bytes) > 0 {
		return true
	}
	for _, value := range secret.Extras {
		if value != "" {
			return true
		}
	}
	return false
}

func (a *WebhookApprover) timeout() time.Duration {
	if a.Timeout <= 0 {
		return webhookDefaultTimeout
	}
	return time.Duration(a.Timeout) * time.Second
}

func (a *WebhookApprover) httpClient() *http.Client {
	client := http.Client{}
	if a.client != nil {
		client = *a.client
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

func buildWebhookRequest(req runtime.ApproveRequest) webhookRequest {
	principalID := req.PrincipalID
	if principalID == "" && req.AgentIP != "" {
		principalID = "peer:" + req.AgentIP
	}
	endpoint, family := "", ""
	if req.Endpoint != nil {
		endpoint = req.Endpoint.Name
		family = req.Endpoint.Family
	}
	rule := ""
	if req.Rule != nil {
		rule = req.Rule.Name
	}
	path := req.Path
	if family == "ssh" {
		// sshSummary can include a bounded stdin preview for dashboard and
		// local HITL use. The webhook MVP excludes body content.
		path, _, _ = strings.Cut(path, " | stdin: ")
	}
	return webhookRequest{
		SchemaVersion: 1,
		Approver:      boundedWebhookText(req.ApproverName, 256),
		Principal: webhookPrincipal{
			ID:          boundedWebhookText(principalID, 512),
			DisplayName: boundedWebhookText(req.PrincipalDisplayName, 256),
			AgentIP:     boundedWebhookText(req.AgentIP, 128),
			Profile:     boundedWebhookText(req.Profile, 256),
		},
		Policy: webhookPolicy{
			Rule:   boundedWebhookText(rule, 256),
			Reason: boundedWebhookText(req.Reason, 4096),
		},
		Target: webhookTarget{
			Endpoint: boundedWebhookText(endpoint, 256),
			Family:   boundedWebhookText(family, 64),
			Host:     boundedWebhookText(req.Host, 1024),
		},
		Action: webhookAction{
			Method:    boundedWebhookText(req.Method, 256),
			Path:      boundedWebhookText(path, 8192),
			UserAgent: boundedWebhookText(req.UA, 1024),
		},
	}
}

func webhookDeny(reason string) runtime.ApproveVerdict {
	return runtime.ApproveVerdict{Decision: "deny", Reason: reason, By: "gateway"}
}

func requireJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("extra JSON value")
	}
	return err
}

func safeWebhookText(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func boundedWebhookText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" || u.Opaque != "" {
		return errors.New("URL must be an absolute HTTPS URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("URL must not contain user info, a query, or a fragment")
	}
	return nil
}

func validateWebhookApprover(decoded any, name string, _ *config.BuildCtx) hcl.Diagnostics {
	a := decoded.(*WebhookApprover)
	var diags hcl.Diagnostics
	if err := validateWebhookURL(a.URL); err != nil {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("invalid webhook approver %q URL", name),
			Detail:   err.Error(),
		})
	}
	if a.Timeout < 0 || a.Timeout > int(webhookMaxTimeout/time.Second) {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  fmt.Sprintf("invalid webhook approver %q timeout", name),
			Detail:   "timeout must be between 1 and 600 seconds when set",
		})
	}
	return diags
}

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "webhook_approver",
		New:     func() any { return &WebhookApprover{} },
		Runtime: (*WebhookApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential},
		},
		Validate: validateWebhookApprover,
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) {
			return d, nil
		},
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*WebhookApprover)
			ri := config.EmitRefIndex()
			b.SetAttributeValue("url", cty.StringVal(a.URL))
			config.SetIdent(b, "credential", ri.Ref(config.KindCredential, a.Credential))
			if a.Timeout != 0 {
				b.SetAttributeValue("timeout", cty.NumberIntVal(int64(a.Timeout)))
			}
		},
	})
}
