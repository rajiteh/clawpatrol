package main

import (
	"net/http"
	"path"
	"strings"
)

type Match struct {
	Method  []string            `yaml:"method,omitempty" json:"method,omitempty"`
	Path    string              `yaml:"path,omitempty" json:"path,omitempty"`
	Query   map[string][]string `yaml:"query,omitempty" json:"query,omitempty"`
	Headers map[string]string   `yaml:"headers,omitempty" json:"headers,omitempty"`
}

func (m *Match) check(req *http.Request) bool {
	if m == nil {
		return true
	}
	if len(m.Method) > 0 {
		ok := false
		for _, x := range m.Method {
			if strings.EqualFold(x, req.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if m.Path != "" {
		ok, _ := path.Match(m.Path, req.URL.Path)
		if !ok {
			return false
		}
	}
	if len(m.Query) > 0 {
		q := req.URL.Query()
		for k, vs := range m.Query {
			got := q.Get(k)
			if got == "" {
				return false
			}
			ok := false
			for _, v := range vs {
				if matchGlob(v, got) {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		}
	}
	for k, v := range m.Headers {
		if !strings.EqualFold(req.Header.Get(k), v) {
			return false
		}
	}
	return true
}

func matchGlob(pat, s string) bool {
	if pat == s {
		return true
	}
	ok, _ := path.Match(pat, s)
	return ok
}

// selectHostRule returns the first matching rule for (host, peerIP).
// Device-scoped rules (Device==peerIP) are checked before globals so
// per-device overrides take precedence over the company-wide policy.
func selectHostRule(rules []Rule, host, peerIP string) *Rule {
	if r := scanHostRule(rules, host, peerIP, true); r != nil {
		return r
	}
	return scanHostRule(rules, host, peerIP, false)
}

func scanHostRule(rules []Rule, host, peerIP string, deviceOnly bool) *Rule {
	for i := range rules {
		if deviceOnly {
			if rules[i].Device == "" || rules[i].Device != peerIP {
				continue
			}
		} else {
			if rules[i].Device != "" {
				continue
			}
		}
		if rules[i].matches(host) {
			return &rules[i]
		}
	}
	return nil
}

// selectRequestRule: same precedence — device-specific request rules
// before globals.
func selectRequestRule(rules []Rule, host, peerIP string, req *http.Request) *Rule {
	if r := scanReqRule(rules, host, peerIP, req, true); r != nil {
		return r
	}
	return scanReqRule(rules, host, peerIP, req, false)
}

func scanReqRule(rules []Rule, host, peerIP string, req *http.Request, deviceOnly bool) *Rule {
	for i := range rules {
		if deviceOnly {
			if rules[i].Device == "" || rules[i].Device != peerIP {
				continue
			}
		} else {
			if rules[i].Device != "" {
				continue
			}
		}
		if !rules[i].matches(host) {
			continue
		}
		if !rules[i].Match.check(req) {
			continue
		}
		return &rules[i]
	}
	return nil
}
