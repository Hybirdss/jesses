// Package web extracts network destinations from WebFetch and
// WebSearch tool-use events.
//
// WebFetch inputs carry a URL directly; WebSearch carries a query
// and the destination is the search engine itself (policy usually
// allows or blocks the engine globally, so we emit one canonical
// destination per search engine).
package web

import (
	"net/url"
	"strings"

	"github.com/Hybirdss/jesses/internal/extractors"
)

// ExtractFetch pulls the URL from a WebFetch-shaped tool event.
func ExtractFetch(raw map[string]any) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	u, _ := input["url"].(string)
	if u == "" {
		return nil, nil
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return []extractors.Destination{{
			Kind: "unknown", Raw: u, Source: "input.url",
		}}, nil
	}
	kind := "https"
	if parsed.Scheme != "" {
		kind = strings.ToLower(parsed.Scheme)
	}
	return []extractors.Destination{{
		Kind:   kind,
		Host:   parsed.Hostname(),
		Port:   parsed.Port(),
		Path:   parsed.Path,
		Raw:    u,
		Source: "input.url",
	}}, nil
}

// ExtractSearch handles WebSearch. The destination is the engine's
// host (Google, Bing, Brave, etc.). When the caller doesn't name an
// engine we assume the harness's configured default and emit
// "search-engine" as a policy-visible pseudo-host.
func ExtractSearch(raw map[string]any) ([]extractors.Destination, error) {
	input, _ := raw["input"].(map[string]any)
	engine, _ := input["engine"].(string)
	query, _ := input["query"].(string)
	host := "search-engine"
	if engine != "" {
		host = strings.ToLower(engine)
	}
	return []extractors.Destination{{
		Kind:   "https",
		Host:   host,
		Raw:    query,
		Source: "input.query",
	}}, nil
}
