package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// fallbackCLIVersion is the last known version of the official CLI. It is
	// used until the npm registry answers, and forever if it never does.
	fallbackCLIVersion = "0.24.1"

	// npmLatestURL is the npm registry endpoint for the official client. The
	// package name came from the commandcode-proxy reference (Phase 1 only has
	// to confirm the official CLI uses the same package).
	npmLatestURL = "https://registry.npmjs.org/command-code/latest"

	// cliVersionRefreshInterval is how often the registry is re-read. It must
	// never be consulted per request: completions only read the cached value.
)

// A var so tests can drive the periodic refresh without waiting 24h.
var cliVersionRefreshInterval = 24 * time.Hour

// VersionProvider resolves the CLI version the upstream expects in the
// x-command-code-version header. Current is safe for concurrent use and never
// blocks on the network; Refresh updates the cached value.
type VersionProvider struct {
	current atomic.Pointer[string]

	// resolved records whether the cached value ever came from a successful
	// registry read (as opposed to the bundled fallback).
	resolved atomic.Bool

	// fetch is the injectable registry read, used by tests.
	fetch func() (string, error)

	// refreshMu serializes refreshes so a ticker and a manual refresh cannot
	// issue overlapping registry requests.
	refreshMu sync.Mutex
}

// newNPMVersionProvider builds a provider reading the given registry URL. An
// empty URL falls back to the official npm package; a nil client gets a
// bounded 10s client so a stalled registry can never wedge a refresh.
func newNPMVersionProvider(url string, client *http.Client) *VersionProvider {
	if url == "" {
		url = npmLatestURL
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &VersionProvider{fetch: func() (string, error) {
		return fetchNPMVersion(client, url)
	}}
}

// NewVersionProvider returns a provider for the official npm package.
func NewVersionProvider() *VersionProvider {
	return newNPMVersionProvider(npmLatestURL, nil)
}

// Current returns the cached version, or the fallback before the first
// successful refresh.
func (v *VersionProvider) Current() string {
	if v == nil {
		return fallbackCLIVersion
	}
	if p := v.current.Load(); p != nil && *p != "" {
		return *p
	}
	return fallbackCLIVersion
}

// Refresh reads the registry and caches the result. Registry failures are
// returned for logging but never clear the previously cached version.
func (v *VersionProvider) Refresh() error {
	if v == nil || v.fetch == nil {
		return fmt.Errorf("no CLI version source configured")
	}
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	version, err := v.fetch()
	if err != nil {
		return err
	}
	if version == "" {
		return fmt.Errorf("npm registry returned an empty version")
	}
	v.current.Store(&version)
	v.resolved.Store(true)
	return nil
}

// Source reports where the current version came from: "npm" once a registry
// read has succeeded, otherwise "fallback".
func (v *VersionProvider) Source() string {
	if v != nil && v.resolved.Load() {
		return "npm"
	}
	return "fallback"
}

// Start refreshes immediately and then every cliVersionRefreshInterval until
// ctx is canceled. Registry errors only produce a [WARN].
func (v *VersionProvider) Start(ctx context.Context) {
	go func() {
		v.refreshLogged()
		ticker := time.NewTicker(cliVersionRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				v.refreshLogged()
			}
		}
	}()
}

func (v *VersionProvider) refreshLogged() {
	if err := v.Refresh(); err != nil {
		log.Printf("[WARN] CLI version refresh failed, keeping %s: %v", v.Current(), err)
	}
}

func fetchNPMVersion(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build npm request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("npm request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("npm registry returned status %d", resp.StatusCode)
	}
	var payload struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode npm response: %w", err)
	}
	if payload.Version == "" {
		return "", fmt.Errorf("npm response carried no version")
	}
	return payload.Version, nil
}
