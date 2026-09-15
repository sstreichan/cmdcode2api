package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestDetectionStore(t *testing.T) *DetectionStore {
	t.Helper()
	return loadDetection(filepath.Join(t.TempDir(), "detection.json"))
}

func isHexOfLen(t *testing.T, value string, n int) bool {
	t.Helper()
	if len(value) != n {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func TestDetectionFingerprintShapeAndStability(t *testing.T) {
	store := newTestDetectionStore(t)
	state, need := store.Ensure("acct-1", "https://api.example")
	if !need {
		t.Fatal("first Ensure must require a handshake")
	}
	if !isHexOfLen(t, state.Fingerprint, 64) {
		t.Fatalf("fingerprint = %q, want 64 hex chars (SHA-256)", state.Fingerprint)
	}
	if state.Profile.CPUCores <= 0 || state.Profile.CPUModel == "" || state.Profile.Timezone == "" {
		t.Fatalf("profile = %#v", state.Profile)
	}
	if !containsInt(fingerprintMemoryGiB, state.Profile.MemoryGiB) {
		t.Fatalf("memory = %d, not from the pool", state.Profile.MemoryGiB)
	}

	store.MarkHandshake("acct-1", "https://api.example")
	again, need := store.Ensure("acct-1", "https://api.example")
	if need {
		t.Fatal("second Ensure in the same window must not require a handshake")
	}
	if again.Fingerprint != state.Fingerprint || again.SessionID != state.SessionID {
		t.Fatalf("state changed without a reason: %#v -> %#v", state, again)
	}

	other, _ := store.Ensure("acct-2", "https://api.example")
	if other.Fingerprint == state.Fingerprint {
		t.Fatal("different accounts must not share a fingerprint")
	}
}

func containsInt(list []int, want int) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

func TestDetectionJitterBoundsAreOneSided(t *testing.T) {
	base := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

	zero := newTestDetectionStore(t)
	zero.now = func() time.Time { return base }
	zero.randInt = func(int) int { return 0 }
	state, _ := zero.Ensure("acct", "https://api.example")
	if got := state.SessionExpiresAt.Sub(base); got != detectionSessionTTL {
		t.Fatalf("session TTL = %s, want exactly %s", got, detectionSessionTTL)
	}
	if got := state.FingerprintRefreshAt.Sub(base); got != detectionFingerprintRefresh {
		t.Fatalf("refresh = %s, want exactly %s", got, detectionFingerprintRefresh)
	}
	zero.MarkHandshake("acct", "https://api.example")
	state, _ = zero.Ensure("acct", "https://api.example")
	if got := state.FingerprintRefreshAt.Sub(base); got != detectionFingerprintRefresh {
		t.Fatalf("refresh after handshake = %s, want exactly %s", got, detectionFingerprintRefresh)
	}

	max := newTestDetectionStore(t)
	max.now = func() time.Time { return base }
	max.randInt = func(n int) int { return n - 1 }
	state, _ = max.Ensure("acct", "https://api.example")
	sessionUpper := detectionSessionTTL + detectionSessionJitter - time.Nanosecond
	if got := state.SessionExpiresAt.Sub(base); got != sessionUpper {
		t.Fatalf("max session TTL = %s, want %s (< %s)", got, sessionUpper, detectionSessionTTL+detectionSessionJitter)
	}
	max.MarkHandshake("acct", "https://api.example")
	state, _ = max.Ensure("acct", "https://api.example")
	refreshUpper := detectionFingerprintRefresh + detectionFingerprintJitter - time.Nanosecond
	if got := state.FingerprintRefreshAt.Sub(base); got != refreshUpper {
		t.Fatalf("max refresh = %s, want %s", got, refreshUpper)
	}
}

func TestDetectionRenewsSessionAfterTTL(t *testing.T) {
	store := newTestDetectionStore(t)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	first, _ := store.Ensure("acct", "https://api.example")
	store.MarkHandshake("acct", "https://api.example")

	// Advance past the session TTL but within the fingerprint refresh window.
	now = now.Add(detectionSessionTTL + detectionSessionJitter + time.Minute)
	second, need := store.Ensure("acct", "https://api.example")
	if !need {
		t.Fatal("an expired session must require a handshake")
	}
	if second.SessionID == first.SessionID {
		t.Fatal("session id must rotate after expiry")
	}
	if projectSlugFromSession(second.SessionID) == projectSlugFromSession(first.SessionID) {
		t.Fatal("project slug must rotate with the session")
	}
	if !second.SessionExpiresAt.After(now) {
		t.Fatalf("new session already expired: %s", second.SessionExpiresAt)
	}
}

func TestDetectionBaseURLChangeRerecords(t *testing.T) {
	store := newTestDetectionStore(t)
	first, _ := store.Ensure("acct", "https://api.one")
	store.MarkHandshake("acct", "https://api.one")

	second, need := store.Ensure("acct", "https://api.two")
	if !need {
		t.Fatal("base_url change must require re-recording")
	}
	if second.Fingerprint == first.Fingerprint || second.SessionID == first.SessionID {
		t.Fatalf("base_url change must reset state: %#v -> %#v", first, second)
	}
	if second.BaseURL != "https://api.two" {
		t.Fatalf("base_url = %q", second.BaseURL)
	}
}

func TestDetectionPersistsWithoutRawKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detection.json")
	store := loadDetection(path)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }
	store.Ensure("acct-1", "https://api.example")
	store.MarkHandshake("acct-1", "https://api.example")
	first, _ := store.State("acct-1")

	reloaded := loadDetection(path)
	got, ok := reloaded.State("acct-1")
	if !ok {
		t.Fatal("state did not survive a reload")
	}
	if got.Fingerprint != first.Fingerprint || got.SessionID != first.SessionID || got.Profile != first.Profile {
		t.Fatalf("reloaded state = %#v, want %#v", got, first)
	}
	if !got.FingerprintRefreshAt.Equal(first.FingerprintRefreshAt) || !got.SessionExpiresAt.Equal(first.SessionExpiresAt) {
		t.Fatalf("deadlines changed across reload: %#v -> %#v", first, got)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"user_secretkey", "ccgw-", "Bearer "} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("detection.json leaked %q: %s", secret, data)
		}
	}
	if !strings.Contains(string(data), "acct-1") {
		t.Fatalf("detection.json is not keyed by account id: %s", data)
	}
}

func TestDetectionCorruptFileRebuilds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "detection.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	store := loadDetection(path)
	if _, ok := store.State("acct"); ok {
		t.Fatal("corrupt file must not yield stale state")
	}
	state, need := store.Ensure("acct", "https://api.example")
	if !need || state.Fingerprint == "" {
		t.Fatalf("store must rebuild after a corrupt file: %#v need=%v", state, need)
	}
}

func TestDetectionForgetAndRerecord(t *testing.T) {
	store := newTestDetectionStore(t)
	first, _ := store.Ensure("acct", "https://api.example")
	store.MarkHandshake("acct", "https://api.example")

	store.Forget("acct")
	if _, ok := store.State("acct"); ok {
		t.Fatal("Forget must remove the entry")
	}
	second, need := store.Ensure("acct", "https://api.example")
	if !need || second.Fingerprint == first.Fingerprint {
		t.Fatal("re-added account must start from a fresh fingerprint")
	}

	store.MarkHandshake("acct", "https://api.example")
	rerecorded, need := store.ReRecord("acct", "https://api.example")
	if !need || rerecorded.Fingerprint == second.Fingerprint {
		t.Fatal("ReRecord must produce a new fingerprint")
	}

	store.MarkHandshake("acct", "https://api.example")
	oldSession := rerecorded.SessionID
	fresh, need := store.NewSession("acct", "https://api.example")
	if !need || fresh.SessionID == oldSession {
		t.Fatal("NewSession must rotate the session id")
	}
}

func TestDetectionSessionIDIsStableThenRotates(t *testing.T) {
	store := newTestDetectionStore(t)
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	store.now = func() time.Time { return now }

	state, _ := store.Ensure("acct", "https://api.example")
	if got := store.SessionID("acct"); got != state.SessionID {
		t.Fatalf("SessionID = %q, want %q", got, state.SessionID)
	}
	store.MarkHandshake("acct", "https://api.example")
	if got := store.SessionID("acct"); got != state.SessionID {
		t.Fatalf("SessionID changed within the window: %q", got)
	}
	now = now.Add(detectionSessionTTL + detectionSessionJitter + time.Minute)
	if got := store.SessionID("acct"); got == state.SessionID {
		t.Fatal("SessionID must rotate after expiry")
	}
}

// ===== handshake integration =====

type handshakeRecorder struct {
	mu    sync.Mutex
	paths []string
	auth  []string
	meta  []http.Header
}

func (r *handshakeRecorder) record(path string, header http.Header) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, path)
	r.auth = append(r.auth, header.Get("Authorization"))
	r.meta = append(r.meta, header.Clone())
}

func (r *handshakeRecorder) counts() (fingerprint, lifecycle, generate int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, path := range r.paths {
		switch path {
		case "/alpha/fingerprint/record":
			fingerprint++
		case "/alpha/lifecycle-events":
			lifecycle++
		case "/alpha/generate":
			generate++
		}
	}
	return
}

func (r *handshakeRecorder) order() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...)
}

func (r *handshakeRecorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

func newHandshakeUpstream(t *testing.T, recorder *handshakeRecorder, handshakeStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r.URL.Path, r.Header)
		if r.URL.Path == "/alpha/generate" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(handshakeStatus)
	}))
}

func TestCCClientFiresHandshakeOnceBeforeCompletion(t *testing.T) {
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusOK)
	defer upstream.Close()

	store := newTestDetectionStore(t)
	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(store)

	req := &ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: TextContent("hi")}}}
	for i := 0; i < 2; i++ {
		if _, _, err := client.Send(context.Background(), req); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}

	fingerprint, lifecycle, generate := recorder.counts()
	if fingerprint != 1 || lifecycle != 1 {
		t.Fatalf("handshake counts = fingerprint %d lifecycle %d, want 1/1", fingerprint, lifecycle)
	}
	if generate != 2 {
		t.Fatalf("generate count = %d, want 2", generate)
	}

	// Both handshakes must complete before the first completion request.
	order := recorder.order()
	firstGenerate := indexOf(order, "/alpha/generate")
	if firstGenerate < 2 {
		t.Fatalf("first generate happened before both handshakes: %v", order)
	}
	before := order[:firstGenerate]
	if indexOf(before, "/alpha/fingerprint/record") < 0 || indexOf(before, "/alpha/lifecycle-events") < 0 {
		t.Fatalf("handshakes missing before first generate: %v", order)
	}

	// Handshake metadata is the reduced set: auth + version/environment only.
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for i, path := range recorder.paths {
		if path == "/alpha/generate" {
			continue
		}
		if !strings.HasPrefix(recorder.auth[i], "Bearer ") {
			t.Fatalf("handshake %s missing Authorization: %q", path, recorder.auth[i])
		}
		if recorder.meta[i].Get("x-session-id") != "" || recorder.meta[i].Get("traceparent") != "" || recorder.meta[i].Get("x-project-slug") != "" {
			t.Fatalf("handshake %s carried full metadata: %v", path, recorder.meta[i])
		}
	}
}

func indexOf(list []string, want string) int {
	for i, value := range list {
		if value == want {
			return i
		}
	}
	return -1
}

func TestCCClientHandshakeFailureDoesNotBlockCompletion(t *testing.T) {
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusInternalServerError)
	defer upstream.Close()

	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(newTestDetectionStore(t))

	if _, _, err := client.Send(context.Background(), &ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: TextContent("hi")}}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	fingerprint, lifecycle, generate := recorder.counts()
	if fingerprint != 1 || lifecycle != 1 || generate != 1 {
		t.Fatalf("counts = %d/%d/%d, want 1/1/1", fingerprint, lifecycle, generate)
	}
}

func TestCCClientHandshakeUnauthorizedDisablesAccount(t *testing.T) {
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusUnauthorized)
	defer upstream.Close()

	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(newTestDetectionStore(t))

	_, _, err := client.Send(context.Background(), &ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: TextContent("hi")}}})
	if err == nil {
		t.Fatal("a 401 handshake must fail the attempt")
	}
	if account := pool.Primary(); account != nil && account.Enabled {
		t.Fatal("account must be disabled after a 401 handshake")
	}
	if _, _, generate := recorder.counts(); generate != 0 {
		t.Fatalf("generate ran despite the 401 handshake: %d", generate)
	}
}

func TestAccountPoolDetectionInvalidation(t *testing.T) {
	store := newTestDetectionStore(t)
	pool := NewAccountPool(nil)
	pool.SetDetectionStore(store)

	account, err := pool.Add("a", "user_key-one", true)
	if err != nil {
		t.Fatal(err)
	}
	store.Ensure(account.ID, "https://api.example")
	store.MarkHandshake(account.ID, "https://api.example")
	if _, ok := store.State(account.ID); !ok {
		t.Fatal("state missing after Ensure")
	}

	pool.Rename(account.ID, "renamed")
	if _, ok := store.State(account.ID); !ok {
		t.Fatal("Rename must not touch detection state")
	}

	// Removing the account drops its state.
	if !pool.Remove(account.ID) {
		t.Fatal("Remove returned false")
	}
	if _, ok := store.State(account.ID); ok {
		t.Fatal("Remove must delete detection state")
	}

	// Rotation drops the old entry and starts fresh under the new id.
	setup, err := pool.Add("b", "user_key-two", true)
	if err != nil {
		t.Fatal(err)
	}
	store.Ensure(setup.ID, "https://api.example")
	store.MarkHandshake(setup.ID, "https://api.example")
	oldFingerprint, _ := store.State(setup.ID)

	newID, err := pool.SetKey(setup.ID, "user_key-three")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.State(setup.ID); ok {
		t.Fatal("SetKey must forget the old key's state")
	}
	if _, ok := store.State(newID); ok {
		t.Fatal("the rotated id must start with no state")
	}
	fresh, need := store.Ensure(newID, "https://api.example")
	if !need || fresh.Fingerprint == oldFingerprint.Fingerprint {
		t.Fatal("rotated key must get a fresh fingerprint")
	}
}

func TestCCClientRecordFingerprintAndLifecycleFireOnceEach(t *testing.T) {
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusOK)
	defer upstream.Close()

	store := newTestDetectionStore(t)
	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(store)
	account := pool.Primary()

	if err := client.RecordFingerprint(context.Background(), account); err != nil {
		t.Fatalf("RecordFingerprint: %v", err)
	}
	if fingerprint, lifecycle, _ := recorder.counts(); fingerprint != 1 || lifecycle != 0 {
		t.Fatalf("after re-record: fingerprint %d lifecycle %d, want 1/0", fingerprint, lifecycle)
	}
	if _, ok := store.NewSession(account.ID, upstream.URL); !ok {
		t.Fatal("NewSession reported no change")
	}
	if err := client.RecordLifecycle(context.Background(), account); err != nil {
		t.Fatalf("RecordLifecycle: %v", err)
	}
	if fingerprint, lifecycle, _ := recorder.counts(); fingerprint != 1 || lifecycle != 1 {
		t.Fatalf("after new session: fingerprint %d lifecycle %d, want 1/1", fingerprint, lifecycle)
	}
}

// ===== store edge cases =====

func TestSecureRandIntBounds(t *testing.T) {
	for _, n := range []int{-5, 0, 1} {
		if got := secureRandInt(n); got != 0 {
			t.Errorf("secureRandInt(%d) = %d, want 0", n, got)
		}
	}
	for i := 0; i < 200; i++ {
		got := secureRandInt(7)
		if got < 0 || got >= 7 {
			t.Fatalf("secureRandInt(7) = %d, out of range", got)
		}
	}
}

func TestDetectionJitterZeroLimit(t *testing.T) {
	store := newTestDetectionStore(t)
	for _, limit := range []time.Duration{0, -time.Second} {
		if got := store.jitter(limit); got != 0 {
			t.Errorf("jitter(%s) = %s, want 0", limit, got)
		}
	}
}

func TestDetectionUnknownAccountLookups(t *testing.T) {
	store := newTestDetectionStore(t)

	if got := store.SessionID("missing"); got != "" {
		t.Fatalf("SessionID(unknown) = %q, want empty", got)
	}
	if _, ok := store.State("missing"); ok {
		t.Fatal("State(unknown) reported ok")
	}
	if state, ok := store.MarkHandshake("missing", "https://api.example"); ok || state.Fingerprint != "" {
		t.Fatalf("MarkHandshake(unknown) = %#v, %v; want empty,false", state, ok)
	}

	// A base_url mismatch is treated like an unknown account.
	store.Ensure("acct", "https://api.one")
	if _, ok := store.MarkHandshake("acct", "https://api.two"); ok {
		t.Fatal("MarkHandshake with a stale base_url must not mutate")
	}
	store.MarkRecorded("acct", "https://api.two")
	state, _ := store.State("acct")
	if state.Recorded {
		t.Fatal("MarkRecorded with a stale base_url must not mutate")
	}

	// Forget on an unknown account is a no-op.
	store.Forget("missing")
	if _, ok := store.State("acct"); !ok {
		t.Fatal("Forget(unknown) removed the wrong entry")
	}
}

func TestDetectionReRecordAndNewSessionSeedMissingEntries(t *testing.T) {
	store := newTestDetectionStore(t)

	for _, name := range []string{"ReRecord", "NewSession"} {
		var (
			state DetectionState
			need  bool
		)
		switch name {
		case "ReRecord":
			state, need = store.ReRecord("fresh", "https://api.one")
		case "NewSession":
			state, need = store.NewSession("fresh", "https://api.one")
		}
		if !need || state.Fingerprint == "" || state.SessionID == "" || state.BaseURL != "https://api.one" {
			t.Fatalf("%s(unknown) = %#v need=%v, want a seeded state", name, state, need)
		}
	}

	// An existing account whose base_url changed is also re-seeded.
	store.Ensure("moved", "https://api.old")
	store.MarkHandshake("moved", "https://api.old")
	before, _ := store.State("moved")
	rotated, need := store.ReRecord("moved", "https://api.new")
	if !need || rotated.BaseURL != "https://api.new" || rotated.Fingerprint == before.Fingerprint {
		t.Fatalf("ReRecord after base_url change = %#v need=%v", rotated, need)
	}
	fresh, need := store.NewSession("moved", "https://api.other")
	if !need || fresh.BaseURL != "https://api.other" || fresh.Fingerprint == rotated.Fingerprint {
		t.Fatalf("NewSession after base_url change = %#v need=%v", fresh, need)
	}
}

func TestDetectionSaveRenameFailureKeepsState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	// The tmp file lands next to the target; clean it up after the test.
	t.Cleanup(func() { _ = os.Remove(target + ".tmp") })

	store := &DetectionStore{accounts: map[string]DetectionState{}, path: target, now: time.Now, randInt: secureRandInt}
	state, need := store.Ensure("acct", "https://api.example")
	if !need || state.Fingerprint == "" {
		t.Fatalf("Ensure = %#v need=%v, want in-memory state", state, need)
	}
	// The tmp write succeeds, so the failure really is the rename.
	if _, err := os.Stat(target + ".tmp"); err != nil {
		t.Fatalf("tmp file was not written: %v", err)
	}
	if _, ok := store.State("acct"); !ok {
		t.Fatal("a failed rename must not drop in-memory state")
	}
}

func TestDetectionSaveWithoutPathAndWithBrokenPath(t *testing.T) {
	// No path configured: state stays in memory and nothing is written.
	memoryOnly := &DetectionStore{accounts: map[string]DetectionState{}, now: time.Now, randInt: secureRandInt}
	state, need := memoryOnly.Ensure("acct", "https://api.example")
	if !need || state.Fingerprint == "" {
		t.Fatalf("Ensure without a path = %#v need=%v", state, need)
	}
	memoryOnly.MarkHandshake("acct", "https://api.example")
	if state, need := memoryOnly.Ensure("acct", "https://api.example"); need {
		t.Fatalf("in-memory Handshake must still suppress the next handshake: %#v", state)
	}

	// An unwritable path must not fail the request; the store keeps working.
	broken := &DetectionStore{
		accounts: map[string]DetectionState{},
		path:     filepath.Join(t.TempDir(), "missing-dir", "detection.json"),
		now:      time.Now,
		randInt:  secureRandInt,
	}
	second, need := broken.Ensure("acct", "https://api.example")
	if !need || second.Fingerprint == "" {
		t.Fatalf("Ensure with an unwritable path = %#v need=%v", second, need)
	}
	if _, ok := broken.State("acct"); !ok {
		t.Fatal("state must be kept even when persistence fails")
	}
}

func TestFingerprintShortAndTimeString(t *testing.T) {
	if got := FingerprintShort(""); got != "" {
		t.Errorf("FingerprintShort(\"\") = %q", got)
	}
	short := strings.Repeat("a", 20)
	if got := FingerprintShort(short); got != short {
		t.Errorf("FingerprintShort(short) = %q, want it unchanged", got)
	}
	long := strings.Repeat("a", 8) + strings.Repeat("b", 48) + strings.Repeat("c", 8)
	if got := FingerprintShort(long); got != strings.Repeat("a", 8)+"…"+strings.Repeat("c", 8) {
		t.Errorf("FingerprintShort(long) = %q", got)
	}

	if got := detectionTimeString(time.Time{}); got != "" {
		t.Errorf("detectionTimeString(zero) = %q, want empty", got)
	}
	zone := time.FixedZone("CET", 2*60*60)
	got := detectionTimeString(time.Date(2026, time.March, 4, 5, 6, 7, 0, zone))
	if got != "2026-03-04T03:06:07Z" {
		t.Errorf("detectionTimeString = %q, want UTC RFC3339", got)
	}
}

// ===== handshake edges =====

func TestHandshakeDedupesConcurrentFirstRequests(t *testing.T) {
	recorder := &handshakeRecorder{}
	var release sync.WaitGroup
	release.Add(1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.record(r.URL.Path, r.Header)
		if r.URL.Path != "/alpha/generate" {
			// Hold the handshake open so both requests contend on the lock.
			release.Wait()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(newTestDetectionStore(t))

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := client.Send(context.Background(), &ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: TextContent("hi")}}})
			errs <- err
		}()
	}

	// Wait until both requests have reached the handshake, then let it finish.
	deadline := time.Now().Add(2 * time.Second)
	for recorder.total() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("no handshake request observed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	release.Done()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Send: %v", err)
		}
	}

	if fingerprint, lifecycle, generate := recorder.counts(); fingerprint != 1 || lifecycle != 1 || generate != 2 {
		t.Fatalf("counts = %d/%d/%d, want 1/1/2 (handshake must not double-fire)", fingerprint, lifecycle, generate)
	}
}

// A request that waits on the per-account handshake lock must skip the
// handshake once the winner has recorded it, instead of firing a second one.
func TestPrepareDetectionSkipsWhenAnotherWorkerFinished(t *testing.T) {
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusOK)
	defer upstream.Close()

	store := newTestDetectionStore(t)
	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(store)
	account := pool.Primary()

	// Hold the lock the way a concurrent in-flight handshake would.
	lock := client.accountHandshakeLock(account.ID)
	lock.Lock()
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.prepareDetection(context.Background(), account)
	}()

	// Wait until the waiter has passed its first Ensure (state now exists).
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := store.State(account.ID); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter never created detection state")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// The winner finishes while the waiter is queued.
	store.MarkHandshake(account.ID, client.BaseURLValue())
	lock.Unlock()

	if err := <-errCh; err != nil {
		t.Fatalf("prepareDetection: %v", err)
	}
	if fingerprint, lifecycle, _ := recorder.counts(); fingerprint != 0 || lifecycle != 0 {
		t.Fatalf("waiter fired a duplicate handshake: %d/%d", fingerprint, lifecycle)
	}
}

func TestRecordFingerprintAndLifecycleEdgeCases(t *testing.T) {
	recorder := &handshakeRecorder{}
	upstream := newHandshakeUpstream(t, recorder, http.StatusInternalServerError)
	defer upstream.Close()

	// A store-less client reports that detection is not configured.
	bare := NewCCClient("user_key-one", upstream.URL)
	account := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}}).Primary()
	for _, err := range []error{
		bare.RecordFingerprint(context.Background(), account),
		bare.RecordLifecycle(context.Background(), account),
	} {
		if err == nil || !strings.Contains(err.Error(), "detection store is not configured") {
			t.Fatalf("store-less record error = %v", err)
		}
	}

	// A failing upstream is surfaced to the caller.
	client := NewCCClientWithPool(NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}}), upstream.URL)
	client.SetDetection(newTestDetectionStore(t))
	acct := client.Pool.Primary()
	if err := client.RecordFingerprint(context.Background(), acct); err == nil {
		t.Fatal("RecordFingerprint must surface an upstream failure")
	}
	if err := client.RecordLifecycle(context.Background(), acct); err == nil {
		t.Fatal("RecordLifecycle must surface an upstream failure")
	}
}

func TestDoHandshakeRequestFailures(t *testing.T) {
	pool := NewAccountPool(nil)

	// Unmarshalable payload.
	broken := NewCCClientWithPool(pool, "https://api.example")
	if err := broken.doHandshakeRequest(context.Background(), fingerprintPath, make(chan int), "user_key"); err == nil || !strings.Contains(err.Error(), "marshal") {
		t.Fatalf("marshal error = %v", err)
	}

	// Unparseable base URL.
	unparseable := NewCCClientWithPool(pool, "://bad")
	if err := unparseable.doHandshakeRequest(context.Background(), fingerprintPath, map[string]string{}, "user_key"); err == nil || !strings.Contains(err.Error(), "build") {
		t.Fatalf("build error = %v", err)
	}

	// Unreachable upstream.
	unreachable := NewCCClientWithPool(pool, "http://127.0.0.1:1")
	if err := unreachable.doHandshakeRequest(context.Background(), fingerprintPath, map[string]string{}, "user_key"); err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("transport error = %v", err)
	}
}

func TestIsHandshakeAuthError(t *testing.T) {
	if isHandshakeAuthError(nil) {
		t.Fatal("nil must not be an auth error")
	}
	if isHandshakeAuthError(context.DeadlineExceeded) {
		t.Fatal("a plain error must not be an auth error")
	}
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		if !isHandshakeAuthError(&upstreamAPIError{Status: status}) {
			t.Fatalf("status %d must be an auth error", status)
		}
	}
	if isHandshakeAuthError(&upstreamAPIError{Status: http.StatusInternalServerError}) {
		t.Fatal("500 must not be an auth error")
	}
}

func TestHandshakePayloadsAreWellFormed(t *testing.T) {
	var fingerprintBody, lifecycleBody map[string]any
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		switch r.URL.Path {
		case "/alpha/fingerprint/record":
			fingerprintBody = payload
		case "/alpha/lifecycle-events":
			lifecycleBody = payload
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	pool := NewAccountPool([]AccountConfig{{Name: "a", APIKey: "user_key-one"}})
	client := NewCCClientWithPool(pool, upstream.URL)
	client.SetDetection(newTestDetectionStore(t))
	if _, _, err := client.Send(context.Background(), &ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: TextContent("hi")}}}); err != nil {
		t.Fatalf("Send: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if fingerprintBody == nil || lifecycleBody == nil {
		t.Fatalf("handshake bodies missing: %v / %v", fingerprintBody, lifecycleBody)
	}
	if thumb, _ := fingerprintBody["thumbmark"].(string); !isHexOfLen(t, thumb, 64) {
		t.Fatalf("thumbmark = %v, want 64 hex chars", fingerprintBody["thumbmark"])
	}
	if fingerprintBody["platform"] != "win32" || fingerprintBody["arch"] != "x64" || fingerprintBody["runtime"] != "cli" {
		t.Fatalf("fingerprint platform fields = %v", fingerprintBody)
	}
	metadata, _ := lifecycleBody["metadata"].(map[string]any)
	if metadata == nil {
		t.Fatalf("lifecycle body missing metadata: %v", lifecycleBody)
	}
	session, _ := metadata["sessionId"].(string)
	if !strings.HasPrefix(session, "sess_") || len(session) != len("sess_")+16 {
		t.Fatalf("lifecycle sessionId = %q, want sess_<16 hex>", session)
	}
	if metadata["mode"] != "interactive" || metadata["cliVersion"] == "" {
		t.Fatalf("lifecycle metadata = %v", metadata)
	}
}
