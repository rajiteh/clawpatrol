package config

import (
	"fmt"
	"time"
)

// CompiledK8sEnrollment is the runtime-friendly, duration-parsed form of
// a kubernetes_token_review enrollment block. Like the OIDC enrollment,
// it is compiled separately from endpoint routing: it authorizes a peer
// into a profile, never a request to an endpoint.
type CompiledK8sEnrollment struct {
	Name     string
	Type     string
	Audience string
	Matches  []CompiledK8sMatch
	// LivenessTimeout is the parsed `liveness_timeout`, or 0 when the
	// operator omitted it (the reaper applies its default in that case).
	LivenessTimeout time.Duration
	// MaxTTL is the parsed `max_ttl`, or 0 when unset. Parsed and stored
	// for a future hard-expiry enforcement pass; not enforced today.
	MaxTTL time.Duration
}

// CompiledK8sMatch is one identity → profile-binding rule.
type CompiledK8sMatch struct {
	Namespace      string
	ServiceAccount string
	ProfileLabel   string
	Profiles       []string
}

func compileK8sEnrollments(cp *CompiledPolicy, p *Policy) error {
	if cp == nil || p == nil || len(p.Enrollments) == 0 {
		return nil
	}
	seen := map[string]bool{}
	emit := func(name string) error {
		if seen[name] {
			return nil
		}
		ent, ok := p.Enrollments[name]
		if !ok || ent == nil {
			return nil
		}
		seen[name] = true
		ke, ok := ent.Body.(*K8sEnrollment)
		if !ok {
			return fmt.Errorf("enrollment %q: unexpected body %T", name, ent.Body)
		}
		liveness, err := parseOptionalDuration(ke.LivenessTimeout)
		if err != nil {
			return fmt.Errorf("enrollment %q liveness_timeout: %w", name, err)
		}
		maxTTL, err := parseOptionalDuration(ke.MaxTTL)
		if err != nil {
			return fmt.Errorf("enrollment %q max_ttl: %w", name, err)
		}
		compiled := &CompiledK8sEnrollment{
			Name:            name,
			Type:            ent.Plugin.Type,
			Audience:        ke.Audience,
			LivenessTimeout: liveness,
			MaxTTL:          maxTTL,
		}
		for _, m := range ke.Matches {
			for _, prof := range m.Profiles {
				if _, ok := cp.Profiles[prof]; !ok {
					return fmt.Errorf("enrollment %q: profile %q not compiled", name, prof)
				}
			}
			compiled.Matches = append(compiled.Matches, CompiledK8sMatch{
				Namespace:      m.Namespace,
				ServiceAccount: m.ServiceAccount,
				ProfileLabel:   m.ProfileLabel,
				Profiles:       append([]string(nil), m.Profiles...),
			})
		}
		cp.K8sEnrollments = append(cp.K8sEnrollments, compiled)
		cp.K8sEnrollmentsByName[name] = compiled
		return nil
	}
	// Follow declaration order (p.Order) for determinism, then sweep any
	// enrollment the order slice missed (defensive — every loaded entry
	// is in Order in practice).
	for _, name := range p.Order {
		if _, ok := p.Enrollments[name]; ok {
			if err := emit(name); err != nil {
				return err
			}
		}
	}
	for name := range p.Enrollments {
		if err := emit(name); err != nil {
			return err
		}
	}
	return nil
}

func parseOptionalDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	return time.ParseDuration(raw)
}
