package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Mock Command Code upstream
// ============================================================================

type upstreamRequest struct {
	Path   string
	Header http.Header
	Body   []byte
}

// mockUpstream mimics the three Command Code endpoints the gateway talks to.
// Tests can override the generate behavior, either globally or per API key.
type mockUpstream struct {
	mu              sync.Mutex
	requests        []upstreamRequest
	handshakeStatus int
	generate        func(w http.ResponseWriter, r *http.Request, apiKey string) bool
}

func newMockUpstream() *mockUpstream {
	return &mockUpstream{handshakeStatus: http.StatusOK}
}

func (m *mockUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	m.mu.Lock()
	m.requests = append(m.requests, upstreamRequest{Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
	handshakeStatus := m.handshakeStatus
	generate := m.generate
	m.mu.Unlock()

	switch r.URL.Path {
	case fingerprintPath, lifecyclePath:
		w.WriteHeader(handshakeStatus)
	case "/alpha/generate":
		if generate != nil && generate(w, r, apiKey) {
			return
		}
		writeDefaultUpstreamStream(w)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeDefaultUpstreamStream(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher := w.(http.Flusher)
	_, _ = io.WriteString(w, `data: {"type":"text-delta","text":"hello"}`+"\n\n")
	_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":10,"outputTokens":3}}`+"\n\n")
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func (m *mockUpstream) recorded(path string) []upstreamRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []upstreamRequest
	for _, request := range m.requests {
		if request.Path == path {
			out = append(out, request)
		}
	}
	return out
}

func (m *mockUpstream) count(path string) int { return len(m.recorded(path)) }

func (m *mockUpstream) order() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	paths := make([]string, 0, len(m.requests))
	for _, request := range m.requests {
		paths = append(paths, request.Path)
	}
	return paths
}

// ============================================================================
// Gateway harness (same middleware order as runServer)
// ============================================================================

type integrationGateway struct {
	server        *httptest.Server
	upstream      *mockUpstream
	pool          *AccountPool
	cc            *CCClient
	keys          *ClientKeyPool
	cfg           *Config
	usage         *UsageTracker
	detection     *DetectionStore
	clientKey     string
	adminPassword string
	detectionPath string
}

// gatewayHost owns everything that outlives a gateway restart: the mock
// upstream and the on-disk state directory. start() boots a fresh gateway on
// top of it, re-reading detection.json the way process startup does.
type gatewayHost struct {
	t             *testing.T
	upstream      *mockUpstream
	upstreamURL   string
	configPath    string
	usagePath     string
	detectionPath string
}

func newGatewayHost(t *testing.T, accounts []AccountConfig) (*gatewayHost, *integrationGateway) {
	t.Helper()

	upstream := newMockUpstream()
	upstreamServer := httptest.NewServer(upstream)
	t.Cleanup(upstreamServer.Close)

	dir := t.TempDir()
	host := &gatewayHost{
		t:             t,
		upstream:      upstream,
		upstreamURL:   upstreamServer.URL,
		configPath:    filepath.Join(dir, "config.yaml"),
		usagePath:     filepath.Join(dir, "usage.json"),
		detectionPath: filepath.Join(dir, "detection.json"),
	}
	return host, host.start(accounts)
}

func newIntegrationGateway(t *testing.T, accounts []AccountConfig) *integrationGateway {
	t.Helper()
	_, gateway := newGatewayHost(t, accounts)
	return gateway
}

func (h *gatewayHost) start(accounts []AccountConfig) *integrationGateway {
	t := h.t
	t.Helper()

	previousConfig := configFile
	configFile = h.configPath
	previousUsage := usageFile
	usageFile = h.usagePath
	t.Cleanup(func() {
		configFile = previousConfig
		usageFile = previousUsage
	})

	cfg := &Config{Host: "localhost", Port: 11434}
	cfg.setAdminPassword("admin-pass-123")
	cfg.SetUpstreamBaseURL(h.upstreamURL)

	clientKey := "ccgw-integration-key"
	keys := NewClientKeyPool([]ClientKeyConfig{{Name: "test", Key: clientKey}})

	pool := NewAccountPool(accounts)
	detection := loadDetection(h.detectionPath)
	pool.SetDetectionStore(detection)

	cc := NewCCClientWithPool(pool, h.upstreamURL)
	cc.SetDetection(detection)
	usage := &UsageTracker{}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	mux.HandleFunc("/v1/chat/completions", handleChatCompletions(cc, cfg, usage))
	mux.HandleFunc("/v1/models", handleModels(cfg))
	mux.HandleFunc("/usage", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(usage.Snapshot())
	})
	adminMux := http.NewServeMux()
	registerAdminRoutes(adminMux, cc, pool, keys, cfg, usage, newLogRing())
	mux.Handle("/admin/", adminAuth(cfg, nil)(adminMux))
	mux.HandleFunc("POST /admin/api/oauth/callback", handleWebOAuthCallback())

	var handler http.Handler = mux
	handler = authMiddleware(cfg, keys)(handler)
	handler = applyInflightLimit(handler)
	handler = securityHeaders()(handler)
	handler = loggingMiddleware(handler)
	handler = corsMiddleware(handler)

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return &integrationGateway{
		server:        server,
		upstream:      h.upstream,
		pool:          pool,
		cc:            cc,
		keys:          keys,
		cfg:           cfg,
		usage:         usage,
		detection:     detection,
		clientKey:     clientKey,
		adminPassword: "admin-pass-123",
		detectionPath: h.detectionPath,
	}
}

func (g *integrationGateway) postChat(t *testing.T, payload ChatRequest, key string) (*http.Response, string) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, g.server.URL+"/v1/chat/completions", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (g *integrationGateway) admin(t *testing.T, method, path string, payload any) (*http.Response, map[string]any) {
	t.Helper()
	var reader io.Reader
	if payload != nil {
		raw, _ := json.Marshal(payload)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, g.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+g.adminPassword)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&decoded)
	return resp, decoded
}

func basicChat(stream bool) ChatRequest {
	return ChatRequest{
		Model:    "m",
		Stream:   stream,
		Messages: []Message{{Role: "user", Content: TextContent("hi")}},
	}
}

// ============================================================================
// Detection handshake through the full gateway
// ============================================================================

func TestIntegrationFirstRequestDoesHandshakeThenCompletion(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})
	accountID := gateway.pool.Primary().ID

	resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "hello") || !strings.Contains(body, "[DONE]") {
		t.Fatalf("stream body = %s", body)
	}

	// Both handshakes completed before the completion request.
	order := gateway.upstream.order()
	firstGenerate := -1
	for i, path := range order {
		if path == "/alpha/generate" {
			firstGenerate = i
			break
		}
	}
	if firstGenerate < 0 {
		t.Fatalf("no completion request recorded: %v", order)
	}
	before := order[:firstGenerate]
	if !containsString(before, fingerprintPath) || !containsString(before, lifecyclePath) {
		t.Fatalf("handshakes missing before completion: %v", order)
	}
	if gateway.upstream.count(fingerprintPath) != 1 || gateway.upstream.count(lifecyclePath) != 1 {
		t.Fatalf("handshake counts = %d/%d, want 1/1", gateway.upstream.count(fingerprintPath), gateway.upstream.count(lifecyclePath))
	}

	// Handshake requests use the reduced metadata set and the account's key.
	handshake := gateway.upstream.recorded(fingerprintPath)[0]
	if handshake.Header.Get("Authorization") != "Bearer user_account_one" {
		t.Fatalf("handshake auth = %q", handshake.Header.Get("Authorization"))
	}
	for _, absent := range []string{"traceparent", "x-session-id", "x-project-slug", "x-co-flag"} {
		if handshake.Header.Get(absent) != "" {
			t.Errorf("handshake carried %s = %q", absent, handshake.Header.Get(absent))
		}
	}

	// Completion carries the full CLI metadata.
	generate := gateway.upstream.recorded("/alpha/generate")[0]
	if generate.Header.Get("x-command-code-version") != fallbackCLIVersion {
		t.Errorf("version = %q", generate.Header.Get("x-command-code-version"))
	}
	if generate.Header.Get("x-co-flag") != "false" || generate.Header.Get("x-taste-learning") != "false" {
		t.Errorf("flags = %q / %q", generate.Header.Get("x-co-flag"), generate.Header.Get("x-taste-learning"))
	}
	if !strings.HasPrefix(generate.Header.Get("x-session-id"), "sess_") {
		t.Errorf("session id = %q, want the per-key session", generate.Header.Get("x-session-id"))
	}
	if !strings.HasPrefix(generate.Header.Get("x-project-slug"), "cc-") {
		t.Errorf("project slug = %q", generate.Header.Get("x-project-slug"))
	}
	if !traceparentPattern.MatchString(generate.Header.Get("traceparent")) {
		t.Errorf("traceparent = %q", generate.Header.Get("traceparent"))
	}

	// CLI envelope values survive the whole path.
	for _, want := range []string{`"memory":null`, `"taste":null`, `"skills":""`, `"max_tokens":64000`} {
		if !strings.Contains(string(generate.Body), want) {
			t.Errorf("cc body missing %s: %s", want, generate.Body)
		}
	}

	// Detection state is persisted keyed by the account id, without the raw key.
	data, err := os.ReadFile(gateway.detectionPath)
	if err != nil {
		t.Fatalf("detection.json: %v", err)
	}
	if !strings.Contains(string(data), accountID) {
		t.Fatalf("detection.json not keyed by account id: %s", data)
	}
	if strings.Contains(string(data), "user_account_one") {
		t.Fatalf("detection.json leaked the raw key: %s", data)
	}

	// Usage is attributed to the account and the client key.
	snapshot := gateway.usage.Snapshot()
	if snapshot.Accounts[accountID].Requests != 1 {
		t.Fatalf("account usage = %#v", snapshot.Accounts[accountID])
	}

	// A second request reuses the state: no new handshakes, same session.
	_, body = gateway.postChat(t, basicChat(true), gateway.clientKey)
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("second stream = %s", body)
	}
	if gateway.upstream.count(fingerprintPath) != 1 || gateway.upstream.count(lifecyclePath) != 1 {
		t.Fatalf("handshake repeated: %d/%d", gateway.upstream.count(fingerprintPath), gateway.upstream.count(lifecyclePath))
	}
	if gateway.upstream.count("/alpha/generate") != 2 {
		t.Fatalf("generate count = %d, want 2", gateway.upstream.count("/alpha/generate"))
	}
	second := gateway.upstream.recorded("/alpha/generate")[1]
	if second.Header.Get("x-session-id") != generate.Header.Get("x-session-id") {
		t.Fatalf("session rotated without a reason: %q -> %q", generate.Header.Get("x-session-id"), second.Header.Get("x-session-id"))
	}
}

func containsString(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

var traceparentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`)

func TestIntegrationPromptCacheKeyWinsAndMarksCacheControl(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	request := basicChat(true)
	request.PromptCacheKey = "client-prompt-cache"
	request.ReasoningEffort = "high"
	resp, body := gateway.postChat(t, request, gateway.clientKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}

	generate := gateway.upstream.recorded("/alpha/generate")[0]
	if got := generate.Header.Get("x-session-id"); got != "client-prompt-cache" {
		t.Fatalf("x-session-id = %q, want the client prompt_cache_key", got)
	}
	if !strings.Contains(string(generate.Body), `"reasoning_effort":"high"`) {
		t.Fatalf("reasoning_effort not forwarded end-to-end: %s", generate.Body)
	}
	if !strings.Contains(string(generate.Body), `"cache_control":{"type":"ephemeral"}`) {
		t.Fatalf("cache_control marker missing: %s", generate.Body)
	}
}

// ============================================================================
// Client auth through the full chain
// ============================================================================

func TestIntegrationClientAuthPaths(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	// x-api-key works and is sufficient.
	raw, _ := json.Marshal(basicChat(true))
	req, _ := http.NewRequest(http.MethodPost, gateway.server.URL+"/v1/chat/completions", bytes.NewReader(raw))
	req.Header.Set("x-api-key", gateway.clientKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := gateway.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("x-api-key status = %d", resp.StatusCode)
	}

	for _, tt := range []struct {
		name string
		key  string
	}{{"sk", "sk-not-a-gateway-key"}, {"unknown", "ccgw-nope"}} {
		resp, _ := gateway.postChat(t, basicChat(true), tt.key)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s key status = %d, want 401", tt.name, resp.StatusCode)
		}
	}
}

// ============================================================================
// Failover together with detection state
// ============================================================================

func TestIntegrationFailoverRunsPerAccountHandshakes(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{
		{Name: "primary", APIKey: "user_key_a"},
		{Name: "backup", APIKey: "user_key_b"},
	})
	gateway.upstream.generate = func(w http.ResponseWriter, r *http.Request, apiKey string) bool {
		if apiKey == "user_key_a" {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"message":"limited"}`)
			return true
		}
		return false
	}

	resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "[DONE]") {
		t.Fatalf("body = %s", body)
	}

	// Both accounts completed their handshake before being used.
	if got := gateway.upstream.count(fingerprintPath); got != 2 {
		t.Fatalf("fingerprint count = %d, want 2 (one per account)", got)
	}
	if got := gateway.upstream.count(lifecyclePath); got != 2 {
		t.Fatalf("lifecycle count = %d, want 2 (one per account)", got)
	}

	// The completion was attempted on A, then B.
	generates := gateway.upstream.recorded("/alpha/generate")
	if len(generates) != 2 {
		t.Fatalf("generate count = %d, want 2", len(generates))
	}
	if generates[0].Header.Get("Authorization") != "Bearer user_key_a" || generates[1].Header.Get("Authorization") != "Bearer user_key_b" {
		t.Fatalf("failover credentials = %q -> %q", generates[0].Header.Get("Authorization"), generates[1].Header.Get("Authorization"))
	}

	// Usage lands on the account that actually answered.
	snapshot := gateway.usage.Snapshot()
	if snapshot.Accounts[gateway.pool.Views()[1].ID].Requests != 1 {
		t.Fatalf("backup account usage = %#v", snapshot.Accounts)
	}
}

// ============================================================================
// Timeout / zero-output / status mapping / limits
// ============================================================================

func TestIntegrationIdleTimeoutReturns429WithoutFailover(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{
		{Name: "a", APIKey: "user_key_a"},
		{Name: "b", APIKey: "user_key_b"},
	})
	gateway.upstream.generate = func(w http.ResponseWriter, r *http.Request, apiKey string) bool {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		return true
	}

	previous := streamIdleTimeout
	streamIdleTimeout = 50 * time.Millisecond
	t.Cleanup(func() { streamIdleTimeout = previous })
	resetTimeoutCounter()

	resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rate_limit_error") {
		t.Fatalf("body = %s", body)
	}
	if resp.Header.Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q", resp.Header.Get("Retry-After"))
	}
	if got := gateway.upstream.count("/alpha/generate"); got != 1 {
		t.Fatalf("generate count = %d, want 1 (no failover on timeout)", got)
	}
	if timeoutCount() == 0 {
		t.Fatal("timeout was not counted")
	}
}

func TestIntegrationZeroOutputGuardThroughServer(t *testing.T) {
	// Each mode gets its own gateway: the guard cools the account down, so a
	// shared pool would never reach upstream on the second request.
	for _, tc := range []struct {
		name   string
		stream bool
	}{
		{name: "stream", stream: true},
		{name: "nonstream", stream: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})
			gateway.upstream.generate = func(w http.ResponseWriter, r *http.Request, apiKey string) bool {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, `data: {"type":"finish","finishReason":"stop","usage":{"inputTokens":10,"outputTokens":0}}`+"\n\n")
				return true
			}

			resp, body := gateway.postChat(t, basicChat(tc.stream), gateway.clientKey)
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
			}
			if !strings.Contains(body, "rate_limit_error") {
				t.Fatalf("body = %s, want rate_limit_error", body)
			}
			if resp.Header.Get("Retry-After") != "10" {
				t.Fatalf("Retry-After = %q, want 10", resp.Header.Get("Retry-After"))
			}
			// The guard must fire on a real upstream response, not a short-circuit.
			if got := gateway.upstream.count("/alpha/generate"); got != 1 {
				t.Fatalf("generate count = %d, want 1", got)
			}
			// The zero-output response must not look like a successful request,
			// but prompt tokens are still booked (anti false billing).
			snapshot := gateway.usage.Snapshot()
			if snapshot.TotalRequests != 0 {
				t.Fatalf("total requests = %d, want 0", snapshot.TotalRequests)
			}
			if snapshot.PromptTokens != 10 {
				t.Fatalf("prompt tokens = %d, want 10", snapshot.PromptTokens)
			}
		})
	}
}

func TestIntegrationStatusMappingThroughServer(t *testing.T) {
	tests := []struct {
		upstream int
		want     int
		typ      string
	}{
		{upstream: http.StatusPaymentRequired, want: http.StatusTooManyRequests, typ: "rate_limit_error"},
		{upstream: http.StatusForbidden, want: http.StatusUnauthorized, typ: "authentication_error"},
		{upstream: http.StatusInternalServerError, want: http.StatusBadGateway, typ: "upstream_error"},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.upstream), func(t *testing.T) {
			gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})
			gateway.upstream.generate = func(w http.ResponseWriter, r *http.Request, apiKey string) bool {
				w.WriteHeader(tt.upstream)
				_, _ = io.WriteString(w, `{"message":"upstream refused"}`)
				return true
			}

			resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey)
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d (body=%s)", resp.StatusCode, tt.want, body)
			}
			if !strings.Contains(body, tt.typ) {
				t.Fatalf("body = %s, want type %s", body, tt.typ)
			}
		})
	}
}

func TestIntegrationInFlightCapThroughServer(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	release := make(chan struct{})
	started := make(chan struct{})
	var releaseOnce sync.Once
	releaseUpstream := func() { releaseOnce.Do(func() { close(release) }) }
	// Unblock the held request even if an assertion below fails, otherwise
	// httptest.Server.Close would wait on it forever.
	defer releaseUpstream()
	gateway.upstream.generate = func(w http.ResponseWriter, r *http.Request, apiKey string) bool {
		close(started)
		<-release
		writeDefaultUpstreamStream(w)
		return true
	}

	previous := maxInflightRequests
	maxInflightRequests = 1
	t.Cleanup(func() { maxInflightRequests = previous })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		gateway.postChat(t, basicChat(true), gateway.clientKey)
	}()
	<-started

	resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("second request status = %d, want 503 (body=%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "server_busy") {
		t.Fatalf("body = %s", body)
	}
	if resp.Header.Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q", resp.Header.Get("Retry-After"))
	}

	// Liveness stays available while the cap is saturated.
	health, err := gateway.server.Client().Get(gateway.server.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("/health status = %d, want 200", health.StatusCode)
	}

	releaseUpstream()
	wg.Wait()
}

// ============================================================================
// Admin detection surface through the full chain
// ============================================================================

func TestIntegrationAdminDetectionActions(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})
	accountID := gateway.pool.Primary().ID

	// Prime detection state with one completion.
	if resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("warmup status = %d, body=%s", resp.StatusCode, body)
	}

	resp, payload := gateway.admin(t, http.MethodGet, "/admin/api/accounts", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("accounts status = %d", resp.StatusCode)
	}
	if !strings.Contains(mustJSON(t, payload), "fingerprint_short") {
		t.Fatalf("accounts payload missing detection state: %v", payload)
	}

	resp, payload = gateway.admin(t, http.MethodGet, "/admin/api/detection", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detection status = %d", resp.StatusCode)
	}
	entry, _ := payload["accounts"].(map[string]any)[accountID].(map[string]any)
	if entry == nil {
		t.Fatalf("detection payload missing account: %v", payload)
	}
	if short, _ := entry["fingerprint_short"].(string); !strings.Contains(short, "…") || len(short) >= 64 {
		t.Fatalf("fingerprint_short = %q", short)
	}

	resp, payload = gateway.admin(t, http.MethodPost, "/admin/api/accounts/"+accountID+"/fingerprint", nil)
	if resp.StatusCode != http.StatusOK || payload["fingerprint"] != float64(1) {
		t.Fatalf("re-record = %d %v", resp.StatusCode, payload)
	}
	if got := gateway.upstream.count(fingerprintPath); got != 2 {
		t.Fatalf("fingerprint count after re-record = %d, want 2", got)
	}
	if got := gateway.upstream.count(lifecyclePath); got != 1 {
		t.Fatalf("lifecycle count after re-record = %d, want 1", got)
	}

	resp, payload = gateway.admin(t, http.MethodPost, "/admin/api/accounts/"+accountID+"/session", nil)
	if resp.StatusCode != http.StatusOK || payload["lifecycle"] != float64(1) {
		t.Fatalf("new session = %d %v", resp.StatusCode, payload)
	}
	if got := gateway.upstream.count(lifecyclePath); got != 2 {
		t.Fatalf("lifecycle count after new session = %d, want 2", got)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// ============================================================================
// Base URL change re-records against the new upstream
// ============================================================================

func TestIntegrationBaseURLChangeRerecords(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	if resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, body=%s", resp.StatusCode, body)
	}

	secondUpstream := newMockUpstream()
	secondServer := httptest.NewServer(secondUpstream)
	t.Cleanup(secondServer.Close)

	resp, payload := gateway.admin(t, http.MethodPut, "/admin/api/settings", map[string]any{"base_url": secondServer.URL})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings status = %d: %v", resp.StatusCode, payload)
	}

	// The old upstream keeps its recorded history; the new one must see the
	// handshake and the completion.
	if gateway.upstream.count(fingerprintPath) != 1 {
		t.Fatalf("old upstream fingerprint count = %d", gateway.upstream.count(fingerprintPath))
	}
	if resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, body=%s", resp.StatusCode, body)
	}
	if secondUpstream.count(fingerprintPath) != 1 || secondUpstream.count(lifecyclePath) != 1 {
		t.Fatalf("new upstream handshakes = %d/%d, want 1/1",
			secondUpstream.count(fingerprintPath), secondUpstream.count(lifecyclePath))
	}
	if secondUpstream.count("/alpha/generate") != 1 {
		t.Fatalf("new upstream generate count = %d", secondUpstream.count("/alpha/generate"))
	}
	if gateway.upstream.count(fingerprintPath) != 1 {
		t.Fatalf("old upstream must not be re-recorded: %d", gateway.upstream.count(fingerprintPath))
	}
}

// ============================================================================
// Key rotation drops the old device identity
// ============================================================================

func TestIntegrationKeyRotationForgetsDetectionState(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})
	oldID := gateway.pool.Primary().ID

	if resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("warmup status = %d, body=%s", resp.StatusCode, body)
	}
	if got := gateway.upstream.count(fingerprintPath); got != 1 {
		t.Fatalf("fingerprint count after warmup = %d, want 1", got)
	}

	resp, payload := gateway.admin(t, http.MethodPatch, "/admin/api/accounts/"+oldID, map[string]any{"api_key": "user_account_two"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation status = %d: %v", resp.StatusCode, payload)
	}
	newID, _ := payload["id"].(string)
	if newID == "" || newID == oldID {
		t.Fatalf("rotation returned id %q (old %q)", newID, oldID)
	}

	// The rotated key must re-record: a shared device profile across keys
	// would make the two keys linkable upstream.
	if resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("post-rotation status = %d, body=%s", resp.StatusCode, body)
	}
	if got := gateway.upstream.count(fingerprintPath); got != 2 {
		t.Fatalf("fingerprint count after rotation = %d, want 2", got)
	}
	if got := gateway.upstream.count(lifecyclePath); got != 2 {
		t.Fatalf("lifecycle count after rotation = %d, want 2", got)
	}
	generates := gateway.upstream.recorded("/alpha/generate")
	if got := generates[len(generates)-1].Header.Get("Authorization"); got != "Bearer user_account_two" {
		t.Fatalf("post-rotation auth = %q", got)
	}

	// The old identity is gone from the detection payload, and the new
	// account id is what the store (and detection.json) is keyed by.
	resp, payload = gateway.admin(t, http.MethodGet, "/admin/api/detection", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detection status = %d", resp.StatusCode)
	}
	accounts, _ := payload["accounts"].(map[string]any)
	if _, stale := accounts[oldID]; stale {
		t.Fatalf("old identity still present after rotation: %v", accounts)
	}
	if _, ok := accounts[newID]; !ok {
		t.Fatalf("new identity missing after rotation: %v", accounts)
	}
	data, err := os.ReadFile(gateway.detectionPath)
	if err != nil {
		t.Fatalf("detection.json: %v", err)
	}
	if strings.Contains(string(data), "user_account_two") {
		t.Fatalf("detection.json leaked the rotated key: %s", data)
	}
}

// ============================================================================
// Process-global consecutive-timeout hint
// ============================================================================

func TestIntegrationConsecutiveTimeoutsAddReduceContextHint(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})
	gateway.upstream.generate = func(w http.ResponseWriter, r *http.Request, apiKey string) bool {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
		return true
	}

	previous := streamIdleTimeout
	streamIdleTimeout = 30 * time.Millisecond
	t.Cleanup(func() {
		streamIdleTimeout = previous
		resetTimeoutCounter()
	})
	resetTimeoutCounter()

	var last string
	for i := 0; i < timeoutHintThreshold; i++ {
		resp, body := gateway.postChat(t, basicChat(true), gateway.clientKey)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("request %d status = %d, body=%s", i+1, resp.StatusCode, body)
		}
		if resp.Header.Get("Retry-After") != "5" {
			t.Fatalf("request %d Retry-After = %q, want 5", i+1, resp.Header.Get("Retry-After"))
		}
		if got := int64(i + 1); timeoutCount() != got {
			t.Fatalf("timeout count after request %d = %d, want %d", i+1, timeoutCount(), got)
		}
		last = body
	}
	if !strings.Contains(last, "reducing context length") {
		t.Fatalf("third timeout body = %s, want the reduce-context hint", last)
	}
}

// ============================================================================
// Body limit through the full chain
// ============================================================================

func TestIntegrationOversizedBodyReturns413(t *testing.T) {
	gateway := newIntegrationGateway(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	previous := maxChatRequestBytes
	maxChatRequestBytes = 1024
	t.Cleanup(func() { maxChatRequestBytes = previous })

	raw := append([]byte(`{"model":"m","messages":[],"pad":"`), bytes.Repeat([]byte("a"), 4096)...)
	raw = append(raw, []byte(`"}`)...)
	req, err := http.NewRequest(http.MethodPost, gateway.server.URL+"/v1/chat/completions", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+gateway.clientKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := gateway.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body=%s)", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "request body too large") {
		t.Fatalf("body = %s", body)
	}
	// The oversized request must never reach upstream.
	if got := gateway.upstream.count("/alpha/generate"); got != 0 {
		t.Fatalf("upstream saw %d requests, want 0", got)
	}
}

// ============================================================================
// Detection state survives a restart
// ============================================================================

func TestIntegrationDetectionStateSurvivesRestart(t *testing.T) {
	host, first := newGatewayHost(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	if resp, body := first.postChat(t, basicChat(true), first.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("warmup status = %d, body=%s", resp.StatusCode, body)
	}
	if fingerprint, lifecycle := first.upstream.count(fingerprintPath), first.upstream.count(lifecyclePath); fingerprint != 1 || lifecycle != 1 {
		t.Fatalf("handshakes after warmup = %d/%d, want 1/1", fingerprint, lifecycle)
	}
	warmup := first.upstream.recorded("/alpha/generate")[0]
	sessionID := warmup.Header.Get("x-session-id")
	if sessionID == "" {
		t.Fatal("warmup request carried no session id")
	}
	_, before := first.admin(t, http.MethodGet, "/admin/api/detection", nil)
	stateBefore, err := os.ReadFile(first.detectionPath)
	if err != nil {
		t.Fatalf("detection.json: %v", err)
	}

	// Restart: a new pool, a new detection store read from disk, and a new
	// HTTP server, all over the same upstream and state directory.
	second := host.start([]AccountConfig{{Name: "a", APIKey: "user_account_one"}})
	if second.detection == first.detection {
		t.Fatal("restart must build a fresh detection store")
	}
	if second.server.URL == first.server.URL {
		t.Fatal("restart must build a fresh server")
	}

	// The restarted store must have read the state back, not started empty.
	loaded, ok := second.detection.State(second.pool.Primary().ID)
	if !ok || !loaded.Recorded {
		t.Fatalf("restarted store did not load the persisted state: %#v ok=%v", loaded, ok)
	}
	if loaded.SessionID != sessionID || loaded.Fingerprint == "" {
		t.Fatalf("loaded state = session %q fingerprint %q, want session %q", loaded.SessionID, loaded.Fingerprint, sessionID)
	}

	if resp, body := second.postChat(t, basicChat(true), second.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("post-restart status = %d, body=%s", resp.StatusCode, body)
	}

	// The persisted state must suppress the handshake: re-recording on every
	// restart would let the upstream correlate the restarts.
	if got := second.upstream.count(fingerprintPath); got != 1 {
		t.Fatalf("fingerprint count after restart = %d, want 1", got)
	}
	if got := second.upstream.count(lifecyclePath); got != 1 {
		t.Fatalf("lifecycle count after restart = %d, want 1", got)
	}

	generates := second.upstream.recorded("/alpha/generate")
	sinceRestart := generates[len(generates)-1]
	if got := sinceRestart.Header.Get("x-session-id"); got != sessionID {
		t.Fatalf("session id after restart = %q, want the persisted %q", got, sessionID)
	}
	if got := sinceRestart.Header.Get("Authorization"); got != "Bearer user_account_one" {
		t.Fatalf("auth after restart = %q", got)
	}
	if !traceparentPattern.MatchString(sinceRestart.Header.Get("traceparent")) {
		t.Fatalf("traceparent after restart = %q", sinceRestart.Header.Get("traceparent"))
	}

	// The full state (fingerprint, profile, deadlines) is unchanged, and no
	// write happened while serving the post-restart request.
	_, after := second.admin(t, http.MethodGet, "/admin/api/detection", nil)
	if mustJSON(t, before) != mustJSON(t, after) {
		t.Fatalf("detection snapshot changed across restart:\nbefore=%s\nafter=%s", mustJSON(t, before), mustJSON(t, after))
	}
	stateAfter, err := os.ReadFile(second.detectionPath)
	if err != nil {
		t.Fatalf("detection.json after restart: %v", err)
	}
	if string(stateAfter) != string(stateBefore) {
		t.Fatalf("detection.json was rewritten:\nbefore=%s\nafter=%s", stateBefore, stateAfter)
	}
}

func TestIntegrationRestartHonoursPersistedSessionExpiry(t *testing.T) {
	host, first := newGatewayHost(t, []AccountConfig{{Name: "a", APIKey: "user_account_one"}})

	if resp, body := first.postChat(t, basicChat(true), first.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("warmup status = %d, body=%s", resp.StatusCode, body)
	}
	warmup := first.upstream.recorded("/alpha/generate")[0]
	oldSession := warmup.Header.Get("x-session-id")
	_, snapshot := first.admin(t, http.MethodGet, "/admin/api/detection", nil)
	fingerprintBefore := fingerprintOf(t, snapshot, first.pool.Primary().ID)

	// Expire only the session: the device identity must be kept, but the
	// gateway has to rotate the session and re-record on the next request.
	expireDetectionSession(t, first.detectionPath)

	second := host.start([]AccountConfig{{Name: "a", APIKey: "user_account_one"}})
	if resp, body := second.postChat(t, basicChat(true), second.clientKey); resp.StatusCode != http.StatusOK {
		t.Fatalf("post-restart status = %d, body=%s", resp.StatusCode, body)
	}

	if got := second.upstream.count(fingerprintPath); got != 2 {
		t.Fatalf("fingerprint count = %d, want 2 (expired session must re-record)", got)
	}
	if got := second.upstream.count(lifecyclePath); got != 2 {
		t.Fatalf("lifecycle count = %d, want 2", got)
	}
	generates := second.upstream.recorded("/alpha/generate")
	newSession := generates[len(generates)-1].Header.Get("x-session-id")
	if newSession == oldSession || newSession == "" {
		t.Fatalf("session id after expiry = %q, want a rotation from %q", newSession, oldSession)
	}

	rotated, _ := second.detection.State(second.pool.Primary().ID)
	if rotated.SessionID != newSession {
		t.Fatalf("persisted session = %q, want the header's %q", rotated.SessionID, newSession)
	}

	_, after := second.admin(t, http.MethodGet, "/admin/api/detection", nil)
	if fingerprintAfter := fingerprintOf(t, after, second.pool.Primary().ID); fingerprintAfter != fingerprintBefore {
		t.Fatalf("fingerprint rotated with the session: %q -> %q", fingerprintBefore, fingerprintAfter)
	}
	if string(mustJSON(t, after)) == string(mustJSON(t, snapshot)) {
		t.Fatal("detection snapshot did not change after the session expired")
	}
}

// fingerprintOf pulls the short fingerprint for an account out of an
// /admin/api/detection payload.
func fingerprintOf(t *testing.T, payload map[string]any, accountID string) string {
	t.Helper()
	accounts, _ := payload["accounts"].(map[string]any)
	entry, _ := accounts[accountID].(map[string]any)
	if entry == nil {
		t.Fatalf("detection payload has no entry for %s: %v", accountID, payload)
	}
	short, _ := entry["fingerprint_short"].(string)
	if short == "" {
		t.Fatalf("detection entry has no fingerprint_short: %v", entry)
	}
	return short
}

// expireDetectionSession rewrites the persisted session deadline into the past
// while leaving the fingerprint refresh deadline alone.
func expireDetectionSession(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read detection.json: %v", err)
	}
	var file map[string]any
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode detection.json: %v", err)
	}
	accounts, _ := file["accounts"].(map[string]any)
	if len(accounts) == 0 {
		t.Fatalf("detection.json has no accounts: %s", data)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	for _, raw := range accounts {
		state, _ := raw.(map[string]any)
		state["session_expires_at"] = past
	}
	out, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("encode detection.json: %v", err)
	}
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatalf("write detection.json: %v", err)
	}
}
