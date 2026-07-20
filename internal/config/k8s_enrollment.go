package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// K8sDefaultProfileLabel is the Pod label a kubernetes_token_review match
// reads the clawpatrol profile from when `profile_label` is omitted.
const K8sDefaultProfileLabel = "clawpatrol.dev/profile"

// k8sEnrollmentType is the enrollment plugin type label.
const k8sEnrollmentType = "kubernetes_token_review"

// K8sEnrollment is the built (canonical) form of a
// `enrollment "kubernetes_token_review" "<name>" { ... }` block. It is
// what the plugin's Build returns and what the runtime and emit paths
// read; the compile pass lowers it further into a CompiledK8sEnrollment.
type K8sEnrollment struct {
	Audience string     `json:"audience"`
	Matches  []K8sMatch `json:"match"`
	// LivenessTimeout / MaxTTL are raw time.ParseDuration strings, empty
	// when the operator omitted them. Both are validated as positive
	// durations at load time; the runtime applies the default liveness
	// window when LivenessTimeout is empty.
	LivenessTimeout string `json:"liveness_timeout,omitempty"`
	MaxTTL          string `json:"max_ttl,omitempty"`
}

// K8sMatch is one identity → profile-binding rule. A Pod is matched on
// namespace + service_account; its profile is then read from the Pod
// label named by ProfileLabel and must appear in Profiles.
type K8sMatch struct {
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	ProfileLabel   string   `json:"profile_label"`
	Profiles       []string `json:"profiles"`
}

// k8sEnrollmentBody is the body of an `enrollment
// "kubernetes_token_review" "<name>"` block. It authorizes Kubernetes
// workloads to self-enroll as transient WireGuard peers by verifying a
// projected ServiceAccount token with the Kubernetes TokenReview API.
type k8sEnrollmentBody struct {
	// Audience is passed to Kubernetes TokenReview and must match the
	// projected ServiceAccount token's audience. Required.
	Audience string `hcl:"audience,optional"`
	// Matches are the repeated `match { ... }` rules. Each binds one
	// namespace + service_account identity to a profile allowlist. At
	// least one is required.
	Matches []k8sMatchBody `hcl:"match,block"`
	// LivenessTimeout is the WireGuard-quiet grace window before an
	// enrolled peer is reaped (time.ParseDuration). Optional; defaults to
	// ~75s (3x the keepalive interval). Liveness is observed from the WG
	// device (rx_bytes progress), not an app-level heartbeat.
	LivenessTimeout string `hcl:"liveness_timeout,optional"`
	// MaxTTL is an optional hard lifetime for enrolled peers
	// (time.ParseDuration). Parsed and stored; enforcement is future
	// work. Validated as a positive duration when set.
	MaxTTL string `hcl:"max_ttl,optional"`
}

// k8sMatchBody is one identity → profile-binding rule inside a
// kubernetes_token_review enrollment.
type k8sMatchBody struct {
	// Namespace the pod must run in. Required.
	Namespace string `hcl:"namespace,optional"`
	// ServiceAccount the pod's token must belong to. Required.
	ServiceAccount string `hcl:"service_account,optional"`
	// ProfileLabel is the Pod label the clawpatrol profile is read from.
	// Optional; defaults to "clawpatrol.dev/profile".
	ProfileLabel string `hcl:"profile_label,optional"`
	// Profiles is the allowlist of profiles a matched pod may bind. The
	// value of the profile_label pod label must appear here. Required
	// (at least one), and each must be a declared `profile "<name>"`.
	Profiles []string `hcl:"profiles,optional"`
}

func init() {
	Register(&Plugin{
		Kind:     KindEnrollment,
		Type:     k8sEnrollmentType,
		New:      func() any { return new(k8sEnrollmentBody) },
		Validate: validateK8sEnrollment,
		Build:    buildK8sEnrollment,
		Emit:     emitK8sEnrollment,
	})
}

func k8sEnrollmentDiag(ctx *BuildCtx, summary, detail string) *hcl.Diagnostic {
	d := &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: detail}
	if ctx != nil && ctx.Block != nil {
		d.Subject = &ctx.Block.DefRange
	}
	return d
}

func validateK8sEnrollment(decoded any, name string, ctx *BuildCtx) hcl.Diagnostics {
	body := decoded.(*k8sEnrollmentBody)
	var diags hcl.Diagnostics

	if strings.TrimSpace(body.Audience) == "" {
		diags = append(diags, k8sEnrollmentDiag(ctx, "Missing enrollment audience",
			fmt.Sprintf("enrollment %q requires `audience` so projected ServiceAccount tokens are scoped to clawpatrol.", name)))
	}
	if len(body.Matches) == 0 {
		diags = append(diags, k8sEnrollmentDiag(ctx, "Missing enrollment match",
			fmt.Sprintf("enrollment %q requires at least one `match { namespace = ..., service_account = ..., profiles = [...] }` block.", name)))
	}
	for i, m := range body.Matches {
		if strings.TrimSpace(m.Namespace) == "" {
			diags = append(diags, k8sEnrollmentDiag(ctx, "Invalid enrollment match",
				fmt.Sprintf("enrollment %q match[%d] is missing `namespace`.", name, i)))
		}
		if strings.TrimSpace(m.ServiceAccount) == "" {
			diags = append(diags, k8sEnrollmentDiag(ctx, "Invalid enrollment match",
				fmt.Sprintf("enrollment %q match[%d] is missing `service_account`.", name, i)))
		}
		if len(m.Profiles) == 0 {
			diags = append(diags, k8sEnrollmentDiag(ctx, "Invalid enrollment match",
				fmt.Sprintf("enrollment %q match[%d] is missing at least one profile.", name, i)))
		}
		for j, prof := range m.Profiles {
			if strings.TrimSpace(prof) == "" {
				diags = append(diags, k8sEnrollmentDiag(ctx, "Invalid enrollment match",
					fmt.Sprintf("enrollment %q match[%d].profiles[%d] is empty.", name, i, j)))
				continue
			}
			// Each listed profile must resolve to a declared
			// `profile "<name>"` — resolved through the symbol table like
			// the OIDC enrollment plugin resolves its target profile.
			if ctx != nil && ctx.Symbols != nil && ctx.Symbols.Get(KindProfile, prof) == nil {
				diags = append(diags, k8sEnrollmentDiag(ctx, "Unknown enrollment profile",
					fmt.Sprintf("enrollment %q match[%d] targets profile %q which is not declared.", name, i, prof)))
			}
		}
	}

	diags = append(diags, validateK8sEnrollmentDuration(ctx, name, "liveness_timeout", body.LivenessTimeout)...)
	diags = append(diags, validateK8sEnrollmentDuration(ctx, name, "max_ttl", body.MaxTTL)...)
	return diags
}

// validateK8sEnrollmentDuration accepts an empty string (attr omitted)
// or a positive Go duration; anything else is a diagnostic.
func validateK8sEnrollmentDuration(ctx *BuildCtx, name, attr, raw string) hcl.Diagnostics {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return hcl.Diagnostics{k8sEnrollmentDiag(ctx, "Invalid enrollment "+attr,
			fmt.Sprintf("enrollment %q %s = %q must be a positive Go duration string such as \"3m\".", name, attr, raw))}
	}
	return nil
}

func buildK8sEnrollment(decoded any, _ string, _ *BuildCtx) (any, hcl.Diagnostics) {
	body := decoded.(*k8sEnrollmentBody)
	out := &K8sEnrollment{
		Audience:        body.Audience,
		LivenessTimeout: body.LivenessTimeout,
		MaxTTL:          body.MaxTTL,
	}
	for _, m := range body.Matches {
		label := strings.TrimSpace(m.ProfileLabel)
		if label == "" {
			label = K8sDefaultProfileLabel
		}
		out.Matches = append(out.Matches, K8sMatch{
			Namespace:      m.Namespace,
			ServiceAccount: m.ServiceAccount,
			ProfileLabel:   label,
			Profiles:       append([]string(nil), m.Profiles...),
		})
	}
	return out, nil
}

func emitK8sEnrollment(body any, _ string, b *hclwrite.Body) {
	ke := body.(*K8sEnrollment)
	b.SetAttributeValue("audience", cty.StringVal(ke.Audience))
	for _, m := range ke.Matches {
		mb := b.AppendNewBlock("match", nil).Body()
		mb.SetAttributeValue("namespace", cty.StringVal(m.Namespace))
		mb.SetAttributeValue("service_account", cty.StringVal(m.ServiceAccount))
		if m.ProfileLabel != "" {
			mb.SetAttributeValue("profile_label", cty.StringVal(m.ProfileLabel))
		}
		mb.SetAttributeValue("profiles", StringListVal(m.Profiles))
	}
	if ke.LivenessTimeout != "" {
		b.SetAttributeValue("liveness_timeout", cty.StringVal(ke.LivenessTimeout))
	}
	if ke.MaxTTL != "" {
		b.SetAttributeValue("max_ttl", cty.StringVal(ke.MaxTTL))
	}
}

// validateEnrollmentGateway enforces the cross-block invariant that
// workload enrollment provisions WireGuard peers, so a `wireguard { ... }`
// data-plane block must be declared whenever any enrollment is configured.
// Mirrors how the OIDC enrollment plugin validates gateway-level
// preconditions after per-block decode.
func validateEnrollmentGateway(gw *Gateway) hcl.Diagnostics {
	if gw == nil || gw.Policy == nil || len(gw.Policy.Enrollments) == 0 {
		return nil
	}
	if gw.Settings == nil || gw.Settings.WireGuard == nil {
		return hcl.Diagnostics{&hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "enrollment requires a wireguard block",
			Detail:   "`enrollment` provisions WireGuard peers; declare a `wireguard { ... }` block for the data plane.",
		}}
	}
	return nil
}
