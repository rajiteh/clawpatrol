package main

import (
	"math/rand"
	"time"
)

// runDemoFeed seeds placeholder agents and emits realistic-looking
// traffic events for them. Bumps registry stats so the dashboard table
// counters tick. Auto-suppresses if real agents appear.
func runDemoFeed(g *Gateway) {
	if g.sink == nil || g.agents == nil {
		return
	}

	type fakeSession struct {
		t, model, title string
		tokIn, tokOut   int64
	}
	type fakeAgent struct {
		ip, host, user, os string
		integrations       []string
		sessions           []fakeSession
	}
	agents := []fakeAgent{
		{
			"100.64.0.10", "macbook-pro", "alice@example.com", "macOS",
			[]string{"claude", "codex", "github"},
			[]fakeSession{
				{"claude", "claude-sonnet-4-5", "refactor auth middleware to support OAuth", 38_421, 12_104},
				{"codex", "gpt-4o", "write unit tests for the parser", 8_103, 1_220},
			},
		},
		{
			"100.64.0.21", "dev-box-01", "alice@example.com", "linux",
			[]string{"claude", "github"},
			[]fakeSession{{"claude", "claude-opus-4", "investigate flaky integration test in CI", 142_311, 28_991}},
		},
		{
			"100.64.0.34", "ci-runner", "bot@example.com", "linux",
			[]string{"github"},
			[]fakeSession{{"shell", "", "deployment pipeline", 0, 0}},
		},
		{
			"100.64.0.42", "win-laptop", "bob@example.com", "windows",
			[]string{"codex"},
			[]fakeSession{{"codex", "gpt-4o-mini", "fix typo in error message", 9_213, 2_044}},
		},
	}
	for _, a := range agents {
		g.agents.seed(a.ip, a.host, a.user, a.os)
		g.agents.setIntegrations(a.ip, a.integrations)
		for _, s := range a.sessions {
			g.agents.seedSession(a.ip, s.t, s.model, s.title, s.tokIn, s.tokOut)
		}
	}

	endpoints := []struct{ host, path, method string }{
		{"api.anthropic.com", "/v1/messages", "POST"},
		{"api.anthropic.com", "/v1/messages", "POST"},
		{"api.openai.com", "/v1/chat/completions", "POST"},
		{"api.openai.com", "/v1/embeddings", "POST"},
		{"api.github.com", "/repos/foo/bar/issues", "GET"},
		{"api.github.com", "/user", "GET"},
		{"raw.githubusercontent.com", "/foo/bar/main/README.md", "GET"},
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	tick := time.NewTicker(700 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		a := agents[rng.Intn(len(agents))]
		ep := endpoints[rng.Intn(len(endpoints))]
		status := []int{200, 200, 200, 200, 201, 304, 400, 429, 500}[rng.Intn(9)]
		mode := "mitm"
		if rng.Intn(5) == 0 {
			mode = "splice"
		}
		in := int64(rng.Intn(8000) + 200)
		out := int64(rng.Intn(40000) + 1000)
		g.sink.Emit(Event{
			Mode:    mode,
			AgentIP: a.ip,
			Host:    ep.host,
			Method:  ep.method,
			Path:    ep.path,
			Status:  status,
			In:      in,
			Out:     out,
			Ms:      int64(rng.Intn(800) + 30),
			Action:  "allow",
		})
		g.agents.bump(a.ip, ep.host, in, out)
	}
}
