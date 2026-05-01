package main

// Human-in-the-loop request approval. Rules with `action: hitl` pause
// the upstream call until an operator approves (or denies) on the
// dashboard. Decisions arrive over a per-request channel; the gateway
// times out after Rule.HITLTimeout (default 60s).
//
// Plugin interface (HITLNotifier) is invoked when a new approval is
// pending — implementations can push a Slack message, web-push, etc.
// The dashboard's SSE stream is the always-on built-in notifier.

import (
	"context"
	"sync"
	"time"
)

type HITLDecision struct {
	Allow  bool
	Reason string
	By     string // user who approved
}

type HITLPending struct {
	ID         string    `json:"id"`
	AgentIP    string    `json:"agent_ip"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	UA         string    `json:"ua,omitempty"`
	BodySample string    `json:"body_sample,omitempty"`
	Reason     string    `json:"reason,omitempty"` // rule.Reason — operator-supplied "why approval needed"
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	decision   chan HITLDecision
}

type HITLNotifier interface {
	Notify(p *HITLPending)
}

type HITLRegistry struct {
	mu        sync.Mutex
	pending   map[string]*HITLPending
	notifiers []HITLNotifier
}

func newHITLRegistry() *HITLRegistry {
	return &HITLRegistry{pending: map[string]*HITLPending{}}
}

func (r *HITLRegistry) Register(n HITLNotifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notifiers = append(r.notifiers, n)
}

// Wait registers a pending approval and blocks until decision OR ctx
// timeout. Notifier plugins are fired (best-effort) before the wait.
func (r *HITLRegistry) Wait(ctx context.Context, p *HITLPending, timeout time.Duration) HITLDecision {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	p.ID = randomString(16)
	p.CreatedAt = time.Now()
	p.ExpiresAt = p.CreatedAt.Add(timeout)
	p.decision = make(chan HITLDecision, 1)

	r.mu.Lock()
	r.pending[p.ID] = p
	notifiers := append([]HITLNotifier(nil), r.notifiers...)
	r.mu.Unlock()

	for _, n := range notifiers {
		go func(n HITLNotifier) { n.Notify(p) }(n)
	}

	defer func() {
		r.mu.Lock()
		delete(r.pending, p.ID)
		r.mu.Unlock()
	}()

	select {
	case d := <-p.decision:
		return d
	case <-time.After(timeout):
		return HITLDecision{Allow: false, Reason: "approval timed out"}
	case <-ctx.Done():
		return HITLDecision{Allow: false, Reason: "request cancelled"}
	}
}

func (r *HITLRegistry) List() []*HITLPending {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*HITLPending, 0, len(r.pending))
	for _, p := range r.pending {
		out = append(out, p)
	}
	return out
}

func (r *HITLRegistry) Decide(id string, d HITLDecision) bool {
	r.mu.Lock()
	p := r.pending[id]
	r.mu.Unlock()
	if p == nil {
		return false
	}
	select {
	case p.decision <- d:
		return true
	default:
		return false
	}
}

// hitlSinkNotifier fan-outs pending approvals onto the gateway's main
// event sink so the dashboard SSE stream picks them up alongside
// regular request events. Mode=hitl_pending.
type hitlSinkNotifier struct{ sink *Sink }

func (n *hitlSinkNotifier) Notify(p *HITLPending) {
	n.sink.Emit(Event{
		Mode:    "hitl_pending",
		Host:    p.Host,
		Method:  p.Method,
		Path:    p.Path,
		AgentIP: p.AgentIP,
		Reason:  p.Reason,
		Action:  "pending",
	})
}

