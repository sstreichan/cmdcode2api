package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newDetectionAdminEnv(t *testing.T) (*httptest.Server, *AccountPool, *CCClient, *handshakeRecorder) {
	t.Helper()
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusOK)
	t.Cleanup(upstream.Close)

	store := newTestDetectionStore(t)
	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	pool.SetDetectionStore(store)
	cc := NewCCClientWithPool(pool, upstream.URL)
	cc.SetDetection(store)
	for _, view := range pool.Views() {
		store.Ensure(view.ID, cc.BaseURLValue())
	}

	mux := http.NewServeMux()
	registerAdminRoutes(mux, cc, pool, NewClientKeyPool(nil), &Config{}, &UsageTracker{}, newLogRing())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, pool, cc, recorder
}

func TestAdminDetectionEndpointShowsShortForm(t *testing.T) {
	srv, pool, _, _ := newDetectionAdminEnv(t)
	account := pool.Primary()

	srv.Client()
	resp, payload := adminRequest(t, srv, "GET", "/admin/api/detection", "admin-pass-123", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	accounts, _ := payload["accounts"].(map[string]any)
	entry, _ := accounts[account.ID].(map[string]any)
	if entry == nil {
		t.Fatalf("account %s missing from detection payload: %v", account.ID, payload)
	}
	short, _ := entry["fingerprint_short"].(string)
	if !strings.Contains(short, "…") {
		t.Fatalf("fingerprint_short = %q, want a shortened hash", short)
	}
	if len(short) >= 64 {
		t.Fatalf("fingerprint_short = %q, must not expose the full hash", short)
	}
	if entry["session_expires_at"] == "" || entry["fingerprint_refresh_at"] == "" {
		t.Fatalf("deadlines missing: %v", entry)
	}
}

func TestAdminRerecordAndNewSessionFireExactlyOneRequest(t *testing.T) {
	srv, pool, cc, recorder := newDetectionAdminEnv(t)
	account := pool.Primary()

	// The account appears in the accounts list with its detection columns.
	resp, payload := adminRequest(t, srv, "GET", "/admin/api/accounts", "admin-pass-123", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("accounts status = %d", resp.StatusCode)
	}
	raw, _ := json.Marshal(payload)
	if !strings.Contains(string(raw), "fingerprint_short") {
		t.Fatalf("accounts payload missing detection state: %s", raw)
	}

	resp, body := adminRequest(t, srv, "POST", "/admin/api/accounts/"+account.ID+"/fingerprint", "admin-pass-123", nil)
	if resp.StatusCode != 200 || body["fingerprint"] != float64(1) {
		t.Fatalf("re-record = %d %v", resp.StatusCode, body)
	}
	if fingerprint, lifecycle, _ := recorder.counts(); fingerprint != 1 || lifecycle != 0 {
		t.Fatalf("after re-record: fingerprint %d lifecycle %d, want 1/0", fingerprint, lifecycle)
	}

	resp, body = adminRequest(t, srv, "POST", "/admin/api/accounts/"+account.ID+"/session", "admin-pass-123", nil)
	if resp.StatusCode != 200 || body["lifecycle"] != float64(1) {
		t.Fatalf("new session = %d %v", resp.StatusCode, body)
	}
	if fingerprint, lifecycle, _ := recorder.counts(); fingerprint != 1 || lifecycle != 1 {
		t.Fatalf("after new session: fingerprint %d lifecycle %d, want 1/1", fingerprint, lifecycle)
	}

	if err := cc.RecordFingerprint(context.Background(), account); err != nil {
		t.Fatalf("direct record: %v", err)
	}
}
