package main

import (
	"bytes"
	"net/http"
	"strings"
)

// scanReplaceBytes runs every Swap entry across b in order. Each
// placeholder is searched verbatim and replaced with resolved secret.
func scanReplaceBytes(b []byte, swaps []Swap) []byte {
	for _, s := range swaps {
		if s.Placeholder == "" {
			continue
		}
		b = bytes.ReplaceAll(b, []byte(s.Placeholder), []byte(resolveTemplate(s.Secret)))
	}
	return b
}

// scanReplaceHeaders rewrites every header value that contains a
// placeholder. Multi-value headers handled per-value.
func scanReplaceHeaders(h http.Header, swaps []Swap) {
	if len(swaps) == 0 {
		return
	}
	for k, vals := range h {
		for i, v := range vals {
			for _, s := range swaps {
				if s.Placeholder == "" {
					continue
				}
				if strings.Contains(v, s.Placeholder) {
					v = strings.ReplaceAll(v, s.Placeholder, resolveTemplate(s.Secret))
				}
			}
			vals[i] = v
		}
		h[k] = vals
	}
}

