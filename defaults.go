package main

import "fmt"

// Built-in integration defaults. Operators reference by name in config:
//
//   integrations: [claude-max, codex]
//
// Each entry contributes its OAuth definition (if any) plus rules. User
// can override any field by also defining the same id in config; user
// values win.

type integrationDefault struct {
	OAuth *OAuthIntegration
	Rules []Rule
}

var defaultIntegrations = map[string]integrationDefault{
	"claude": {
		OAuth: &OAuthIntegration{
			ID:     "claude",
			Type:   "oauth2",
			Header: "Authorization",
			Prefix: "Bearer ",
			OAuth: OAuthConfig{
				ClientID:     "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
				AuthURL:      "https://claude.ai/oauth/authorize",
				TokenURL:     "https://console.anthropic.com/v1/oauth/token",
				RedirectURI:  "https://console.anthropic.com/oauth/code/callback",
				Scopes:       []string{"org:create_api_key", "user:profile", "user:inference"},
				RefreshToken: "{{secret:CLAUDE_REFRESH}}",
			},
		},
		Rules: []Rule{
			{
				Host:  "api.anthropic.com",
				Auth:  "claude",
				Track: "claude_usage",
			},
		},
	},

	"codex": {
		OAuth: &OAuthIntegration{
			ID:     "codex",
			Type:   "oauth2",
			Header: "Authorization",
			Prefix: "Bearer ",
			OAuth: OAuthConfig{
				ClientID:     "app_EMoamEEZ73f0CkXaXp7hrann",
				AuthURL:      "https://auth.openai.com/oauth/authorize",
				TokenURL:     "https://auth.openai.com/oauth/token",
				RedirectURI:  "http://localhost:1455/auth/callback",
				Scopes:       []string{"openid", "profile", "email", "offline_access"},
				RefreshToken: "{{secret:CODEX_REFRESH}}",
			},
		},
		Rules: []Rule{
			{Host: "api.openai.com", Auth: "codex", Track: "openai_usage"},
			// Codex CLI uses wss://chatgpt.com/backend-api/codex/responses.
			// Cloudflare flags non-browser TLS fingerprints; we use
			// uTLS (HelloChrome_Auto) for upstream — see utls.go.
			{Host: "chatgpt.com", WSScan: true, Track: "codex_ws_usage"},
		},
	},

	"github": {
		// gh CLI's published OAuth client_id (no secret needed —
		// GitHub's OAuth device flow is designed for public clients).
		// Source: https://github.com/cli/cli — Iv1.b507a08c87ecfe98 is
		// public knowledge; we mirror gh's approach so tokens carry the
		// same scopes (repo, gist, read:org, workflow).
		OAuth: &OAuthIntegration{
			ID:     "github",
			Type:   "oauth2",
			Header: "Authorization",
			Prefix: "Bearer ",
			Flow:   "device",
			OAuth: OAuthConfig{
				// gh CLI's OAuth App client_id (public, supports device flow).
				// See github.com/cli/cli/internal/authflow/flow.go.
				ClientID:  "178c6fc778ccc68e1d6a",
				DeviceURL: "https://github.com/login/device/code",
				TokenURL:  "https://github.com/login/oauth/access_token",
				Scopes:    []string{"repo", "read:org", "gist", "workflow"},
			},
		},
		Rules: []Rule{
			{Host: "api.github.com", Auth: "github"},
			{Host: "raw.githubusercontent.com", Auth: "github"},
		},
	},
}

// expandDefaults merges built-in defaults for ids in cfg.IntegrationNames
// into the config. Existing user-defined entries with same id win.
func expandDefaults(cfg *Config) error {
	have := map[string]bool{}
	for _, o := range cfg.OAuth {
		have[o.ID] = true
	}

	for _, name := range cfg.IntegrationNames {
		def, ok := defaultIntegrations[name]
		if !ok {
			return fmt.Errorf("unknown integration: %q (available: %v)", name, defaultIntegrationKeys())
		}
		if def.OAuth != nil && !have[def.OAuth.ID] {
			cfg.OAuth = append(cfg.OAuth, *def.OAuth)
			have[def.OAuth.ID] = true
		}
		cfg.Rules = append(cfg.Rules, def.Rules...)
	}
	return nil
}

func defaultIntegrationKeys() []string {
	out := make([]string, 0, len(defaultIntegrations))
	for k := range defaultIntegrations {
		out = append(out, k)
	}
	return out
}

func defaultOAuthByID(id string) *OAuthIntegration {
	if d, ok := defaultIntegrations[id]; ok && d.OAuth != nil {
		return d.OAuth
	}
	return nil
}

func defaultOAuthKeys() []string {
	out := []string{}
	for k, d := range defaultIntegrations {
		if d.OAuth != nil {
			out = append(out, k)
		}
	}
	return out
}
