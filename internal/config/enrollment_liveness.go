package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
)

// Enrollment liveness is shared across all enrollment authorizer types (not
// just kubernetes_token_review): every enrolled peer is kept alive by
// symmetric WireGuard keepalive, and the gateway reaps a peer whose receive
// counter has been quiet for a whole number of keepalives. Expressing the
// reap horizon as a count keeps the safety ratio an integer invariant that
// can't be misconfigured. A new authorizer type reuses these knobs, the
// derivation, and the reaper by declaring the two attrs on its block and
// registering an EnrollmentLiveness during compile — the per-authorizer
// tuning stays inside each enrollment block.
const (
	// EnrollmentDefaultKeepalive is the persistent-keepalive interval applied
	// to enrolled peers (both directions) when keepalive_interval is omitted.
	EnrollmentDefaultKeepalive = 25 * time.Second
	// EnrollmentMinKeepalive is the floor for keepalive_interval — below this
	// keepalive traffic is pure overhead with no liveness benefit.
	EnrollmentMinKeepalive = 10 * time.Second
	// EnrollmentDefaultReapCount is the number of missed keepalives before an
	// enrolled peer is reaped when keepalive_reap_count is omitted.
	EnrollmentDefaultReapCount = 3
	// EnrollmentMinReapCount is the smallest non-zero reap count. Below 2 a
	// single dropped keepalive would reap a live peer; 0 disables reaping.
	EnrollmentMinReapCount = 2
)

// EnrollmentLiveness is the resolved keepalive/reap tuning for one enrollment
// authorizer. It is populated by each authorizer type's compile pass and
// indexed by authorizer name on the CompiledPolicy, so the reaper and the
// register-time keepalive passdown resolve it without knowing the type.
type EnrollmentLiveness struct {
	// KeepaliveInterval is the resolved persistent-keepalive interval.
	KeepaliveInterval time.Duration
	// ReapCount is the resolved missed-keepalive count before reap; 0 means
	// reaping (and the client's self-heal escalation) is disabled.
	ReapCount int
}

// LivenessWindow is the derived rx-quiet grace window before an enrolled peer
// is reaped (KeepaliveInterval × ReapCount), or 0 when reaping is disabled.
func (l EnrollmentLiveness) LivenessWindow() time.Duration {
	if l.ReapCount <= 0 {
		return 0
	}
	return l.KeepaliveInterval * time.Duration(l.ReapCount)
}

// resolveEnrollmentLiveness applies defaults to the raw keepalive_interval +
// keepalive_reap_count knobs. Range validation happens at load time via the
// validateEnrollment* helpers; this only fills in the defaults.
func resolveEnrollmentLiveness(keepaliveRaw string, reapCount *int) (EnrollmentLiveness, error) {
	ka, err := parseOptionalDuration(keepaliveRaw)
	if err != nil {
		return EnrollmentLiveness{}, err
	}
	if ka == 0 {
		ka = EnrollmentDefaultKeepalive
	}
	rc := EnrollmentDefaultReapCount
	if reapCount != nil {
		rc = *reapCount
	}
	return EnrollmentLiveness{KeepaliveInterval: ka, ReapCount: rc}, nil
}

// enrollmentDiag builds an hcl error diagnostic anchored at the enrollment
// block, shared by every authorizer type's validation.
func enrollmentDiag(ctx *BuildCtx, summary, detail string) *hcl.Diagnostic {
	d := &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: detail}
	if ctx != nil && ctx.Block != nil {
		d.Subject = &ctx.Block.DefRange
	}
	return d
}

// validateEnrollmentKeepaliveInterval accepts an empty string (attr omitted)
// or a Go duration ≥ EnrollmentMinKeepalive.
func validateEnrollmentKeepaliveInterval(ctx *BuildCtx, name, raw string) hcl.Diagnostics {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return hcl.Diagnostics{enrollmentDiag(ctx, "Invalid enrollment keepalive_interval",
			fmt.Sprintf("enrollment %q keepalive_interval = %q must be a positive Go duration string such as \"25s\".", name, raw))}
	}
	if d < EnrollmentMinKeepalive {
		return hcl.Diagnostics{enrollmentDiag(ctx, "Invalid enrollment keepalive_interval",
			fmt.Sprintf("enrollment %q keepalive_interval = %q is below the %s minimum.", name, raw, EnrollmentMinKeepalive))}
	}
	return nil
}

// validateEnrollmentReapCount accepts nil (attr omitted), 0 (reaping
// disabled), or an integer ≥ EnrollmentMinReapCount. A count of 1 would reap
// a peer after a single missed keepalive, so it is rejected.
func validateEnrollmentReapCount(ctx *BuildCtx, name string, rc *int) hcl.Diagnostics {
	if rc == nil || *rc == 0 {
		return nil
	}
	if *rc < EnrollmentMinReapCount {
		return hcl.Diagnostics{enrollmentDiag(ctx, "Invalid enrollment keepalive_reap_count",
			fmt.Sprintf("enrollment %q keepalive_reap_count = %d must be 0 (disable reaping) or ≥ %d; a smaller value would reap a live peer after a single missed keepalive.", name, *rc, EnrollmentMinReapCount))}
	}
	return nil
}
