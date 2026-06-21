package credentials

import (
	"net/http"
	"testing"

	"github.com/denoland/clawpatrol/internal/config/runtime"
)

func TestHeaderTokenMatchPlaceholder(t *testing.T) {
	plugin := &HeaderToken{Header: "PRIVATE-TOKEN"}

	req := &runtime.Request{Headers: http.Header{"Private-Token": {"PH_prod"}}}
	if !plugin.MatchPlaceholder(req, "PH_prod") {
		t.Fatal("expected exact configured header value to match")
	}

	req = &runtime.Request{Headers: http.Header{"Private-Token": {"prefix PH_prod suffix"}}}
	if plugin.MatchPlaceholder(req, "PH_prod") {
		t.Fatal("embedded placeholder should not match")
	}

	req = &runtime.Request{Headers: http.Header{"X-Other": {"PH_prod"}}}
	if plugin.MatchPlaceholder(req, "PH_prod") {
		t.Fatal("placeholder in unrelated header should not match")
	}
}

func TestHeaderTokenMatchPlaceholderWithPrefix(t *testing.T) {
	plugin := &HeaderToken{Header: "Authorization", Prefix: "Token "}

	req := &runtime.Request{Headers: http.Header{"Authorization": {"Token PH_prod"}}}
	if !plugin.MatchPlaceholder(req, "PH_prod") {
		t.Fatal("expected exact prefixed header value to match")
	}

	req = &runtime.Request{Headers: http.Header{"Authorization": {"PH_prod"}}}
	if plugin.MatchPlaceholder(req, "PH_prod") {
		t.Fatal("placeholder without configured prefix should not match")
	}
}
