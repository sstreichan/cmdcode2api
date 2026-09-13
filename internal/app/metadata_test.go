package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
)

var errTestRandom = errors.New("random source unavailable")

var traceparentRe = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`)

func TestCLIRequestMetadataApplyGoldenHeaders(t *testing.T) {
	meta := CLIRequestMetadata{
		Version:       "0.24.1",
		Environment:   "production",
		SessionID:     "sess-abc",
		ProjectSlug:   "cc-0123456789ab",
		Traceparent:   "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		CoFlag:        false,
		TasteLearning: false,
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.commandcode.ai/alpha/generate", nil)
	if err != nil {
		t.Fatal(err)
	}
	meta.Apply(req)

	want := map[string]string{
		"Content-Type":           "application/json",
		"x-command-code-version": "0.24.1",
		"x-cli-environment":      "production",
		"x-co-flag":              "false",
		"x-taste-learning":       "false",
		"x-session-id":           "sess-abc",
		"x-project-slug":         "cc-0123456789ab",
		"traceparent":            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	}
	for name, value := range want {
		if got := req.Header.Get(name); got != value {
			t.Errorf("header %s = %q, want %q", name, got, value)
		}
	}
	if got := req.Header.Get("x-cmd-zdr"); got != "" {
		t.Errorf("x-cmd-zdr = %q, want absent when ZDR is off", got)
	}
}

func TestCLIRequestMetadataApplyZDROptional(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://x/", nil)
	CLIRequestMetadata{Version: "v", Environment: "production", ZDREnabled: true}.Apply(req)
	if got := req.Header.Get("x-cmd-zdr"); got != "1" {
		t.Fatalf("x-cmd-zdr = %q, want 1", got)
	}
}

func TestNewTraceparentFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		trace, err := newTraceparent()
		if err != nil {
			t.Fatalf("newTraceparent: %v", err)
		}
		if !traceparentRe.MatchString(trace) {
			t.Fatalf("traceparent = %q, want W3C 00-<32hex>-<16hex>-01", trace)
		}
		if seen[trace] {
			t.Fatalf("traceparent %q repeated across requests", trace)
		}
		seen[trace] = true
	}
}

func TestProjectSlugDerivesFromSessionWithoutLocalData(t *testing.T) {
	first := projectSlugFromSession("sess-abc")
	if first == "" {
		t.Fatal("project slug must not be empty")
	}
	if first != projectSlugFromSession("sess-abc") {
		t.Fatal("project slug must be deterministic for one session")
	}
	if first == projectSlugFromSession("sess-other") {
		t.Fatal("different sessions must produce different slugs")
	}

	wd, _ := os.Getwd()
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	lower := strings.ToLower(first)
	for label, value := range map[string]string{"working dir": wd, "hostname": host, "username": user} {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		for _, fragment := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' || r == '.' || r == '_' || r == '-' }) {
			if len(fragment) >= 4 && strings.Contains(lower, fragment) {
				t.Fatalf("project slug %q leaks %s fragment %q", first, label, fragment)
			}
		}
	}
}

func TestResolveSessionIDOrder(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		cacheKey string
		perKey   string
		want     string
	}{
		{name: "x-session-id wins", headers: map[string]string{"x-session-id": "one"}, cacheKey: "abcdefgh", perKey: "per", want: "one"},
		{name: "claude header next", headers: map[string]string{"x-claude-code-session-id": "two"}, cacheKey: "abcdefgh", want: "two"},
		{name: "session_id next", headers: map[string]string{"session_id": "three"}, cacheKey: "abcdefgh", want: "three"},
		{name: "prompt_cache_key long enough", cacheKey: "cachekey", perKey: "per", want: "cachekey"},
		{name: "short prompt_cache_key ignored", cacheKey: "short", perKey: "per", want: "per"},
		{name: "per-key session fallback", perKey: "per", want: "per"},
		{name: "empty when nothing", want: ""},
		{name: "header beats prompt cache", headers: map[string]string{"x-session-id": "h"}, cacheKey: "cachekey", perKey: "per", want: "h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			for name, value := range tt.headers {
				header.Set(name, value)
			}
			if got := resolveSessionID(header, tt.cacheKey, tt.perKey); got != tt.want {
				t.Fatalf("resolveSessionID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCLIRequestMetadataHandshakeIsReduced(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://x/alpha/lifecycle-events", nil)
	CLIRequestMetadata{
		Version:     "0.24.1",
		Environment: "production",
		SessionID:   "sess",
		ProjectSlug: "cc-abc",
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		ZDREnabled:  true,
	}.ApplyHandshake(req)

	for _, name := range []string{"traceparent", "x-session-id", "x-project-slug", "x-co-flag", "x-taste-learning"} {
		if got := req.Header.Get(name); got != "" {
			t.Errorf("handshake must not carry %s, got %q", name, got)
		}
	}
	for name, want := range map[string]string{
		"Content-Type":           "application/json",
		"x-command-code-version": "0.24.1",
		"x-cli-environment":      "production",
		"x-cmd-zdr":              "1",
	} {
		if got := req.Header.Get(name); got != want {
			t.Errorf("handshake header %s = %q, want %q", name, got, want)
		}
	}
}

func TestCCClientSendAppliesClientMetadata(t *testing.T) {
	var mu sync.Mutex
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := NewCCClient("test-key", upstream.URL)
	inbound := http.Header{}
	inbound.Set("x-session-id", "client-session")

	_, _, err := client.SendWithHeaders(context.Background(), &ChatRequest{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: TextContent("hello")}},
	}, inbound)
	if err != nil {
		t.Fatalf("SendWithHeaders: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen == nil {
		t.Fatal("upstream never received a request")
	}
	if got := seen.Get("x-session-id"); got != "client-session" {
		t.Errorf("x-session-id = %q, want client-session", got)
	}
	if got := seen.Get("x-command-code-version"); got != fallbackCLIVersion {
		t.Errorf("x-command-code-version = %q, want %q", got, fallbackCLIVersion)
	}
	if got := seen.Get("x-cli-environment"); got != "production" {
		t.Errorf("x-cli-environment = %q, want production", got)
	}
	if got := seen.Get("x-co-flag"); got != "false" {
		t.Errorf("x-co-flag = %q, want false", got)
	}
	if got := seen.Get("x-taste-learning"); got != "false" {
		t.Errorf("x-taste-learning = %q, want false", got)
	}
	if !traceparentRe.MatchString(seen.Get("traceparent")) {
		t.Errorf("traceparent = %q, want W3C trace context", seen.Get("traceparent"))
	}
	if seen.Get("x-project-slug") == "" {
		t.Error("x-project-slug must be set")
	}
}

func TestCCClientSessionIDFallsBackToPromptCacheKey(t *testing.T) {
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := NewCCClient("test-key", upstream.URL)
	if _, _, err := client.Send(context.Background(), &ChatRequest{
		Model:          "test-model",
		Messages:       []Message{{Role: "user", Content: TextContent("hello")}},
		PromptCacheKey: "prompt-cache-key",
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := seen.Get("x-session-id"); got != "prompt-cache-key" {
		t.Fatalf("x-session-id = %q, want the prompt cache key", got)
	}
}

func TestCCClientZDRFromEnv(t *testing.T) {
	t.Setenv("CMD_ZDR", "1")
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := NewCCClient("test-key", upstream.URL)
	if _, _, err := client.Send(context.Background(), &ChatRequest{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: TextContent("hello")}},
	}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := seen.Get("x-cmd-zdr"); got != "1" {
		t.Fatalf("x-cmd-zdr = %q, want 1", got)
	}
}

func TestCCClientZDRFromInboundHeader(t *testing.T) {
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := NewCCClient("test-key", upstream.URL)
	inbound := http.Header{}
	inbound.Set("x-cmd-zdr", "1")
	if _, _, err := client.SendWithHeaders(context.Background(), &ChatRequest{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: TextContent("hello")}},
	}, inbound); err != nil {
		t.Fatalf("SendWithHeaders: %v", err)
	}
	if got := seen.Get("x-cmd-zdr"); got != "1" {
		t.Fatalf("x-cmd-zdr = %q, want 1", got)
	}
}

func TestNewTraceparentFailureDegradesGracefully(t *testing.T) {
	previous := randomHexSource
	t.Cleanup(func() { randomHexSource = previous })

	fail := func(int) (string, error) { return "", errTestRandom }

	// Failing on the trace id and on the span id must both report an error.
	for _, run := range []string{"trace-id", "span-id"} {
		calls := 0
		randomHexSource = func(n int) (string, error) {
			calls++
			if (run == "trace-id" && calls == 1) || (run == "span-id" && calls == 2) {
				return "", errTestRandom
			}
			return previous(n)
		}
		if _, err := newTraceparent(); err == nil {
			t.Fatalf("newTraceparent with %s failing = nil error", run)
		}
	}

	// A missing trace must not fail the request: the header stays absent while
	// everything else is still populated.
	randomHexSource = fail
	client := NewCCClient("user_key", "https://api.example")
	meta := client.newRequestMetadata(http.Header{}, "prompt-cache-key-123", "sess_per_key")
	if meta.Traceparent != "" {
		t.Fatalf("traceparent = %q, want empty", meta.Traceparent)
	}
	if meta.Version == "" || meta.Environment != cliEnvironmentHeader {
		t.Fatalf("metadata lost its essentials: %#v", meta)
	}
	if meta.SessionID != "prompt-cache-key-123" || meta.ProjectSlug == "" {
		t.Fatalf("session metadata = %#v", meta)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.example/alpha/generate", nil)
	if err != nil {
		t.Fatal(err)
	}
	meta.Apply(req)
	if got := req.Header.Get(headerTraceparent); got != "" {
		t.Fatalf("traceparent header = %q, want absent", got)
	}
}

func TestBoolStringAndTruthyEnv(t *testing.T) {
	if got := boolString(true); got != "true" {
		t.Errorf("boolString(true) = %q", got)
	}
	if got := boolString(false); got != "false" {
		t.Errorf("boolString(false) = %q", got)
	}

	for _, in := range []string{"1", "true", "TRUE", "yes", "On", " 1 "} {
		if !truthyEnv(in) {
			t.Errorf("truthyEnv(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "0", "false", "no", "off", "enabled"} {
		if truthyEnv(in) {
			t.Errorf("truthyEnv(%q) = true, want false", in)
		}
	}
}
