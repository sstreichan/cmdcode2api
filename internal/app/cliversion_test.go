package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVersionProviderUsesNPMVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Path; got != "/command-code/latest" {
			t.Errorf("request path = %q, want /command-code/latest", got)
		}
		_, _ = w.Write([]byte(`{"name":"command-code","version":"0.31.0"}`))
	}))
	defer srv.Close()

	provider := newNPMVersionProvider(srv.URL+"/command-code/latest", nil)
	if got := provider.Current(); got != fallbackCLIVersion {
		t.Fatalf("Current() before refresh = %q, want fallback %q", got, fallbackCLIVersion)
	}
	if err := provider.Refresh(); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := provider.Current(); got != "0.31.0" {
		t.Fatalf("Current() = %q, want 0.31.0", got)
	}
}

func TestVersionProviderFallsBackOnErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "server error", handler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{name: "garbage json", handler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"version":`))
		}},
		{name: "empty version", handler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"name":"command-code"}`))
		}},
		{name: "not found", handler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			provider := newNPMVersionProvider(srv.URL, nil)
			if err := provider.Refresh(); err == nil {
				t.Fatal("Refresh() = nil, want an error")
			}
			if got := provider.Current(); got != fallbackCLIVersion {
				t.Fatalf("Current() = %q, want fallback %q", got, fallbackCLIVersion)
			}
		})
	}

	// A transport error must behave like any other registry failure.
	provider := newNPMVersionProvider("http://127.0.0.1:1", &http.Client{Timeout: 100 * time.Millisecond})
	if err := provider.Refresh(); err == nil {
		t.Fatal("Refresh() = nil, want a transport error")
	}
	if got := provider.Current(); got != fallbackCLIVersion {
		t.Fatalf("Current() = %q, want fallback %q", got, fallbackCLIVersion)
	}
}

func TestVersionProviderRefreshIsRaceFree(t *testing.T) {
	var fetches atomic.Int64
	provider := &VersionProvider{fetch: func() (string, error) {
		fetches.Add(1)
		time.Sleep(time.Millisecond)
		return "0.30.0", nil
	}}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = provider.Current()
			}
			_ = provider.Refresh()
		}()
	}
	wg.Wait()
	if got := provider.Current(); got != "0.30.0" {
		t.Fatalf("Current() = %q, want 0.30.0", got)
	}
}

func TestVersionProviderStartRefreshesAndStops(t *testing.T) {
	var fetches atomic.Int64
	provider := &VersionProvider{fetch: func() (string, error) {
		fetches.Add(1)
		return "0.29.0", nil
	}}

	ctx, cancel := context.WithCancel(context.Background())
	provider.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for provider.Current() != "0.29.0" {
		if time.Now().After(deadline) {
			t.Fatalf("startup refresh never landed, Current() = %q", provider.Current())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if fetches.Load() != 1 {
		t.Fatalf("startup fetches = %d, want 1", fetches.Load())
	}
	cancel()
}

// The fallback must be the only place the hardcoded version survives, so a
// stale literal can never be sent again.
func TestCLIVersionLiteralOnlyExistsAsFallback(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	occurrences := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		count := strings.Count(string(data), `"`+fallbackCLIVersion+`"`)
		if name == "cliversion.go" {
			if count != 1 {
				t.Fatalf("cliversion.go has %d fallback literals, want exactly 1", count)
			}
			continue
		}
		occurrences += count
	}
	if occurrences != 0 {
		t.Fatalf("hardcoded CLI version literal appears %d time(s) outside cliversion.go", occurrences)
	}
	if fallbackCLIVersion != "0.24.1" {
		t.Fatalf("fallbackCLIVersion = %q, want the last known 0.24.1", fallbackCLIVersion)
	}
}

func TestVersionProviderNilAndUnconfigured(t *testing.T) {
	var nilProvider *VersionProvider
	if got := nilProvider.Current(); got != fallbackCLIVersion {
		t.Fatalf("nil Current() = %q, want fallback", got)
	}
	if got := nilProvider.Source(); got != "fallback" {
		t.Fatalf("nil Source() = %q, want fallback", got)
	}
	if err := nilProvider.Refresh(); err == nil {
		t.Fatal("nil Refresh() = nil, want an error")
	}

	// A provider without a fetch function cannot refresh.
	unconfigured := &VersionProvider{}
	if err := unconfigured.Refresh(); err == nil || !strings.Contains(err.Error(), "no CLI version source") {
		t.Fatalf("unconfigured Refresh() = %v", err)
	}
	if got := unconfigured.Source(); got != "fallback" {
		t.Fatalf("unconfigured Source() = %q, want fallback", got)
	}

	// Empty URL and nil client fall back to the official package + default client.
	defaulted := newNPMVersionProvider("", nil)
	if defaulted.fetch == nil {
		t.Fatal("defaulted provider has no fetch function")
	}
	if got := defaulted.Current(); got != fallbackCLIVersion {
		t.Fatalf("defaulted Current() = %q, want fallback", got)
	}

	// An empty cached value is treated as "not resolved yet".
	empty := &VersionProvider{fetch: func() (string, error) { return "1.2.3", nil }}
	blank := ""
	empty.current.Store(&blank)
	if got := empty.Current(); got != fallbackCLIVersion {
		t.Fatalf("Current() with an empty cache = %q, want fallback", got)
	}
}

func TestVersionProviderRejectsEmptyVersionAndKeepsCache(t *testing.T) {
	empty := &VersionProvider{fetch: func() (string, error) { return "", nil }}
	if err := empty.Refresh(); err == nil || !strings.Contains(err.Error(), "empty version") {
		t.Fatalf("Refresh() with an empty version = %v", err)
	}
	if empty.Source() != "fallback" {
		t.Fatalf("an empty version must not resolve the provider: %q", empty.Source())
	}

	// A later failure must keep the cached value and report where it came from.
	calls := 0
	flaky := &VersionProvider{fetch: func() (string, error) {
		calls++
		if calls == 1 {
			return "0.30.0", nil
		}
		return "", errors.New("registry down")
	}}
	if err := flaky.Refresh(); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	flaky.refreshLogged() // must only log, not clear the cache
	if got := flaky.Current(); got != "0.30.0" {
		t.Fatalf("Current() after a failed refresh = %q, want the cached 0.30.0", got)
	}
	if got := flaky.Source(); got != "npm" {
		t.Fatalf("Source() = %q, want npm", got)
	}

	// refreshLogged on an unconfigured provider logs and changes nothing.
	(&VersionProvider{}).refreshLogged()
}

func TestVersionProviderStartRefreshesPeriodically(t *testing.T) {
	previous := cliVersionRefreshInterval
	cliVersionRefreshInterval = 10 * time.Millisecond
	t.Cleanup(func() { cliVersionRefreshInterval = previous })

	var fetches atomic.Int64
	provider := &VersionProvider{fetch: func() (string, error) {
		fetches.Add(1)
		return "0.33.0", nil
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for fetches.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("periodic refresh never fired: %d fetches", fetches.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
}

func TestFetchNPMVersionBadURL(t *testing.T) {
	if _, err := fetchNPMVersion(http.DefaultClient, "://bad"); err == nil || !strings.Contains(err.Error(), "build npm request") {
		t.Fatalf("fetchNPMVersion error = %v", err)
	}
}

func TestAdminCLIVersionEndpoints(t *testing.T) {
	version := "0.27.0"
	provider := &VersionProvider{fetch: func() (string, error) { return version, nil }}
	if err := provider.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	cc := NewCCClientWithPool(NewAccountPool(nil), "https://api.commandcode.test")
	cc.SetVersionProvider(provider)
	mux := http.NewServeMux()
	registerAdminRoutes(mux, cc, NewAccountPool(nil), NewClientKeyPool(nil), &Config{}, &UsageTracker{}, newLogRing())
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, payload := adminRequest(t, srv, "GET", "/admin/api/cliversion", "admin-pass-123", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if payload["version"] != "0.27.0" || payload["source"] != "npm" || payload["fallback"] != fallbackCLIVersion {
		t.Fatalf("payload = %v", payload)
	}

	// A manual refresh picks up the new registry value.
	version = "0.28.0"
	resp, payload = adminRequest(t, srv, "POST", "/admin/api/cliversion/refresh", "admin-pass-123", nil)
	if resp.StatusCode != 200 || payload["version"] != "0.28.0" {
		t.Fatalf("refresh payload = %v (status %d)", payload, resp.StatusCode)
	}

	// A failing refresh keeps advertising the cached value and reports why.
	provider.fetch = func() (string, error) { return "", errors.New("registry down") }
	resp, payload = adminRequest(t, srv, "POST", "/admin/api/cliversion/refresh", "admin-pass-123", nil)
	if resp.StatusCode != 200 || payload["version"] != "0.28.0" || payload["error"] == nil {
		t.Fatalf("failed-refresh payload = %v (status %d)", payload, resp.StatusCode)
	}
}

func TestCCClientSendsProviderVersionWithoutFetchingPerRequest(t *testing.T) {
	var fetches atomic.Int64
	provider := &VersionProvider{fetch: func() (string, error) {
		fetches.Add(1)
		return "0.28.0", nil
	}}
	if err := provider.Refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	var seen []string
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("x-command-code-version"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	client := NewCCClient("test-key", upstream.URL)
	client.SetVersionProvider(provider)

	for i := 0; i < 100; i++ {
		if _, err := client.doSend(context.Background(), []byte(`{}`), "test-key", client.newRequestMetadata(nil, "", "")); err != nil {
			t.Fatalf("doSend %d: %v", i, err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 100 {
		t.Fatalf("upstream saw %d requests, want 100", len(seen))
	}
	for i, version := range seen {
		if version != "0.28.0" {
			t.Fatalf("request %d version = %q, want 0.28.0", i, version)
		}
	}
	if fetches.Load() != 1 {
		t.Fatalf("registry fetches = %d for 100 completions, want exactly 1", fetches.Load())
	}
}
