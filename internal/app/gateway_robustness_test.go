package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ===== key hygiene =====

func TestEnvHelpersFallBackOnBadValues(t *testing.T) {
	// envInt
	t.Setenv("CC_TEST_INT", "7")
	if got := envInt("CC_TEST_INT", 3); got != 7 {
		t.Errorf("envInt(valid) = %d, want 7", got)
	}
	for _, value := range []string{"abc", "-1", ""} {
		t.Setenv("CC_TEST_INT", value)
		if got := envInt("CC_TEST_INT", 3); got != 3 {
			t.Errorf("envInt(%q) = %d, want the fallback 3", value, got)
		}
	}

	// envDurationMS
	t.Setenv("CC_TEST_MS", "250")
	if got := envDurationMS("CC_TEST_MS", time.Second); got != 250*time.Millisecond {
		t.Errorf("envDurationMS(valid) = %s, want 250ms", got)
	}
	// 0 is a legal explicit value (it disables the limit).
	t.Setenv("CC_TEST_MS", "0")
	if got := envDurationMS("CC_TEST_MS", time.Second); got != 0 {
		t.Errorf("envDurationMS(0) = %s, want 0", got)
	}
	for _, value := range []string{"abc", "-5"} {
		t.Setenv("CC_TEST_MS", value)
		if got := envDurationMS("CC_TEST_MS", time.Second); got != time.Second {
			t.Errorf("envDurationMS(%q) = %s, want the fallback 1s", value, got)
		}
	}
}

func TestLogZeroOutputFailureAndPartialUsage(t *testing.T) {
	// A nil account must not panic.
	logZeroOutputFailure(nil)

	account := newAccount("acct", "user_key", true)
	logZeroOutputFailure(account)
	if got := account.Errors.Load(); got != 1 {
		t.Fatalf("account error counter = %d, want 1", got)
	}

	// The usage tracker implements the partial recorder: tokens booked, no request.
	tracker := &UsageTracker{}
	recordPartialUsage(tracker, 11, 0, 4, 5)
	snapshot := tracker.Snapshot()
	if snapshot.TotalRequests != 0 {
		t.Fatalf("partial record counted a request: %d", snapshot.TotalRequests)
	}
	if snapshot.PromptTokens != 11 || snapshot.CacheReadTokens != 4 || snapshot.CacheWriteTokens != 5 {
		t.Fatalf("partial record tokens = %#v", snapshot)
	}

	// A plain recorder (no RecordPartial) falls back to a full Record.
	plain := &plainUsageRecorder{}
	recordPartialUsage(plain, 1, 2, 3, 4)
	if plain.requests != 1 {
		t.Fatalf("plain recorder requests = %d, want 1", plain.requests)
	}
}

func TestLogRobustnessConfigReportsLimits(t *testing.T) {
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })

	logRobustnessConfig()

	out := buf.String()
	for _, want := range []string{"gateway limits:", "stream_idle=", "nonstream_idle=", "max_inflight=", "body_limit=", "drain_timeout_ms="} {
		if !strings.Contains(out, want) {
			t.Fatalf("startup log %q missing %q", out, want)
		}
	}
}

func TestResolveAccountKeyWarnOnlyEdges(t *testing.T) {
	previous := requireUserAccountKeys
	requireUserAccountKeys = false
	t.Cleanup(func() { requireUserAccountKeys = previous })

	// A non-user_ key is kept as-is (warn only) so upgrades do not lock out.
	got, err := resolveAccountKey("legacy", "  sk-legacy-key  ")
	if err != nil || got != "sk-legacy-key" {
		t.Fatalf("resolveAccountKey(warn-only) = %q, %v", got, err)
	}
	// Blank is rejected in every mode.
	if _, err := resolveAccountKey("blank", "   "); err == nil {
		t.Fatal("blank key must be rejected in warn-only mode")
	}
	if _, err := resolveAccountKey("blank", ""); err == nil {
		t.Fatal("empty key must be rejected in warn-only mode")
	}

	// Strict mode rejects instead of keeping a decorated value.
	requireUserAccountKeys = true
	if _, err := resolveAccountKey("legacy", "sk-legacy-key"); err == nil {
		t.Fatal("strict mode must reject a non-user_ key")
	}
	if got, err := resolveAccountKey("ok", "Bearer user_strict_key"); err != nil || got != "user_strict_key" {
		t.Fatalf("strict mode rejected a valid key: %q, %v", got, err)
	}
}

// plainUsageRecorder implements usageRecorder but not partialUsageRecorder.
type plainUsageRecorder struct{ requests int }

func (r *plainUsageRecorder) Record(prompt, completion, cacheRead, cacheWrite int) { r.requests++ }

func TestNormalizeAccountKey(t *testing.T) {
	valid := []struct{ in, want string }{
		{"user_abc-1_2", "user_abc-1_2"},
		{"  user_x  ", "user_x"},
		{"Bearer user_x", "user_x"},
		{"https://api.commandcode.ai/provider/v1/user_x", "user_x"},
		{"token_user_abc", "user_abc"},
	}
	for _, tt := range valid {
		got, err := normalizeAccountKey(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("normalizeAccountKey(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
	for _, in := range []string{"sk-abc", "user_", "foo", "", "   "} {
		if got, err := normalizeAccountKey(in); err == nil {
			t.Errorf("normalizeAccountKey(%q) = %q, want an error", in, got)
		}
	}
}

func TestAccountKeyStrictWritePathRejects(t *testing.T) {
	previous := requireUserAccountKeys
	requireUserAccountKeys = true
	t.Cleanup(func() { requireUserAccountKeys = previous })

	pool := NewAccountPool(nil)
	if _, err := pool.Add("bad", "sk-abc", true); err == nil {
		t.Fatal("Add must reject a non-user_ key in strict mode")
	}
	if pool.Len() != 0 {
		t.Fatal("no account may be created for a rejected key")
	}
	if _, err := pool.Add("ok", "user_good", true); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := pool.SetKey(pool.Views()[0].ID, "sk-bad"); err == nil {
		t.Fatal("SetKey must reject a non-user_ key in strict mode")
	}
}

func TestAccountKeyWarnOnlyLoadPathAccepts(t *testing.T) {
	// Default (warn-only) keeps existing installations working.
	pool := NewAccountPool([]AccountConfig{{Name: "legacy", APIKey: "sk-legacy"}})
	if pool.Len() != 1 {
		t.Fatal("legacy key must stay loadable")
	}
	if account := pool.Primary(); account == nil || !account.Enabled {
		t.Fatal("legacy account must remain enabled")
	}
}

func TestAuthMiddlewareAcceptsXAPIKeyAndNormalizes(t *testing.T) {
	keys := NewClientKeyPool([]ClientKeyConfig{{Name: "k", Key: "ccgw-0123456789abcdef"}})
	cfg := &Config{}
	handler := authMiddleware(cfg, keys)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{name: "bearer", headers: map[string]string{"Authorization": "Bearer ccgw-0123456789abcdef"}, want: 200},
		{name: "x-api-key", headers: map[string]string{"x-api-key": "ccgw-0123456789abcdef"}, want: 200},
		{name: "normalized path", headers: map[string]string{"Authorization": "Bearer  ccgw-0123456789abcdef/v1"}, want: 200},
		{name: "sk rejected", headers: map[string]string{"x-api-key": "sk-abc"}, want: 401},
		{name: "empty", headers: map[string]string{}, want: 401},
		{name: "unknown", headers: map[string]string{"x-api-key": "ccgw-unknown"}, want: 401},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestCORSPreflightAllowsClientHeaders(t *testing.T) {
	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	allowed := rec.Header().Get("Access-Control-Allow-Headers")
	for _, header := range []string{"x-api-key", "x-cmd-zdr", "Authorization"} {
		if !strings.Contains(strings.ToLower(allowed), strings.ToLower(header)) {
			t.Errorf("CORS allow-headers %q missing %s", allowed, header)
		}
	}
}

// ===== status mapping =====

func TestUpstreamStatusMapping(t *testing.T) {
	tests := []struct {
		upstream int
		status   int
		typ      string
		retry    string
	}{
		{upstream: 402, status: 429, typ: "rate_limit_error"},
		{upstream: 403, status: 401, typ: "authentication_error"},
		{upstream: 422, status: 400, typ: "invalid_request_error"},
		{upstream: 500, status: 502, typ: "upstream_error"},
		{upstream: 502, status: 502, typ: "upstream_error"},
		{upstream: 503, status: 503, typ: "temporarily_unavailable"},
		{upstream: 429, status: 429, typ: "rate_limit_error", retry: "30"},
	}
	for _, tt := range tests {
		got := normalizeUpstreamError(tt.upstream, []byte(`{"message":"x"}`), http.Header{})
		if got.Status != tt.status || got.Type != tt.typ {
			t.Errorf("upstream %d -> status %d type %q; want %d %q", tt.upstream, got.Status, got.Type, tt.status, tt.typ)
		}
		if tt.retry != "" && got.RetryAfter != tt.retry {
			t.Errorf("upstream %d Retry-After = %q, want %q", tt.upstream, got.RetryAfter, tt.retry)
		}
	}
}

// ===== idle timeouts & zero-output =====

func newGatewayEnv(t *testing.T, upstream http.HandlerFunc) (*httptest.Server, *Config, *UsageTracker) {
	t.Helper()
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	cfg := &Config{}
	cfg.SetUpstreamBaseURL(srv.URL)
	return srv, cfg, &UsageTracker{}
}

func chatBody(t *testing.T, stream bool) []byte {
	t.Helper()
	body, err := json.Marshal(ChatRequest{
		Model:    "m",
		Stream:   stream,
		Messages: []Message{{Role: "user", Content: TextContent("hi")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestStreamIdleTimeoutBeforeFirstFrameReturns429(t *testing.T) {
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":1,"outputTokens":1}}`+"\n\n")
	})
	previous := streamIdleTimeout
	streamIdleTimeout = 50 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = previous })

	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "rate_limit_error") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q, want 5", rec.Header().Get("Retry-After"))
	}
}

func TestStreamIdleTimeoutMidStreamEmitsErrorFrame(t *testing.T) {
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, `data: {"type":"text-delta","text":"hello"}`+"\n\n")
		flusher.Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":1,"outputTokens":1}}`+"\n\n")
	})
	previous := streamIdleTimeout
	streamIdleTimeout = 50 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = previous })

	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (headers already sent)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "upstream_timeout") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "[DONE]") {
		t.Fatalf("timed-out stream must not send [DONE]: %s", rec.Body.String())
	}
}

func TestIdleWatchdogResetsOnChunks(t *testing.T) {
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		for i := 0; i < 6; i++ {
			_, _ = io.WriteString(w, `: keepalive`+"\n\n")
			_, _ = io.WriteString(w, `data: {"type":"text-delta","text":"x"}`+"\n\n")
			flusher.Flush()
			time.Sleep(20 * time.Millisecond)
		}
		_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":1,"outputTokens":6}}`+"\n\n")
		flusher.Flush()
	})
	previous := streamIdleTimeout
	streamIdleTimeout = 80 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = previous })

	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "[DONE]") {
		t.Fatalf("trickling stream failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "finish_reason") {
		t.Fatalf("stream did not finish: %s", rec.Body.String())
	}
}

func TestNonStreamIdleTimeoutReturns429(t *testing.T) {
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
	})
	previous := nonStreamIdleTimeout
	nonStreamIdleTimeout = 50 * time.Millisecond
	t.Cleanup(func() { nonStreamIdleTimeout = previous })

	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, false)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
}

func TestZeroOutputGuardStrict(t *testing.T) {
	finishOnly := `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":10,"outputTokens":0}}` + "\n\n"
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, finishOnly)
	})
	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)

	// Streaming without any written frame: a real 429 is still possible.
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("stream zero-output status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("Retry-After = %q, want 10", rec.Header().Get("Retry-After"))
	}

	// Non-streaming: the buffered path can always return a real 429.
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, false)))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("nonstream zero-output status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestZeroOutputGuardAfterFirstFrameEmitsErrorFrame(t *testing.T) {
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, `data: {"type":"text-delta","text":"partial"}`+"\n\n")
		flusher.Flush()
		_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":10,"outputTokens":0}}`+"\n\n")
		flusher.Flush()
	})
	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "zero_output") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestZeroOutputUsageNullsInputTokens(t *testing.T) {
	usage := Usage{PromptTokens: 120, TotalTokens: 120, PromptTokensDetails: &PromptTokensDetails{CachedTokens: 30}}
	got := zeroOutputUsage(usage)
	if got.PromptTokens != 0 || got.TotalTokens != 0 || got.PromptTokensDetails != nil {
		t.Fatalf("zero-output usage = %#v, want input/cache nulled", got)
	}
	if got.CompletionTokens != 0 {
		t.Fatalf("completion = %d", got.CompletionTokens)
	}
}

func TestConsecutiveTimeoutHintIsProcessGlobal(t *testing.T) {
	resetTimeoutCounter()
	for i := 0; i < 3; i++ {
		recordTimeout()
	}
	if hint := timeoutHintFor(); !strings.Contains(hint, "reducing context") {
		t.Fatalf("hint after 3 timeouts = %q, want the reduce-context hint", hint)
	}
	resetTimeoutCounter()
	if hint := timeoutHintFor(); hint != "" {
		t.Fatalf("hint after reset = %q, want empty", hint)
	}
	recordTimeout()
	recordTimeout()
	if hint := timeoutHintFor(); hint != "" {
		t.Fatalf("hint before threshold = %q, want empty", hint)
	}
}

// ===== in-flight cap & body limit =====

func TestInFlightCapReturnsServerBusy(t *testing.T) {
	release := make(chan struct{})
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":1,"outputTokens":1}}`+"\n\n")
	})
	previous := maxInflightRequests
	maxInflightRequests = 1
	t.Cleanup(func() { maxInflightRequests = previous })

	cc := NewCCClient("user_testkey", srv.URL)
	handler := applyInflightLimit(handleChatCompletions(cc, cfg, usage))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}()
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "server_busy") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if rec.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	close(release)
	wg.Wait()
}

func TestRequestTooLargeReturns413(t *testing.T) {
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	previous := maxChatRequestBytes
	maxChatRequestBytes = 1024
	t.Cleanup(func() { maxChatRequestBytes = previous })

	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)
	big := append([]byte(`{"model":"m","messages":[],"pad":"`), bytes.Repeat([]byte("a"), 4096)...)
	big = append(big, []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(big))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestUpstreamAbortOnClientDisconnectIsNotATimeout(t *testing.T) {
	started := make(chan struct{})
	srv, cfg, usage := newGatewayEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	cc := NewCCClient("user_testkey", srv.URL)
	handler := handleChatCompletions(cc, cfg, usage)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody(t, true))).WithContext(ctx)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()
	<-started
	resetTimeoutCounter()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after client disconnect")
	}
	if timeoutCount() != 0 {
		t.Fatalf("client disconnect counted as a timeout: %d", timeoutCount())
	}
}
