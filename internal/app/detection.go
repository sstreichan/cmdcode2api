package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Detection state lives in detection.json next to config.yaml/usage.json. It is
// keyed by Account.ID, so the raw key never touches disk.
const (
	detectionSessionTTL         = 12 * time.Hour
	detectionSessionJitter      = 1 * time.Hour
	detectionFingerprintRefresh = 8 * time.Hour
	detectionFingerprintJitter  = 2 * time.Hour

	detectionPlatform  = "win32"
	detectionArch      = "x64"
	detectionOSRelease = "10.0.22631"
	detectionRuntime   = "cli"
	collectorVersion   = 1
)

// detectionFile is a var so tests can redirect persistence to a temp dir.
var detectionFile = "detection.json"

var fingerprintMemoryGiB = []int{8, 16, 24, 32, 48, 64}

type fingerprintCPU struct {
	Model string
	Cores int
}

var fingerprintCPUs = []fingerprintCPU{
	{"i7-12650H", 10},
	{"i5-12400F", 6},
	{"i9-13900K", 24},
	{"Ryzen 7 5800X3D", 8},
	{"Ryzen 5 5600X", 6},
	{"i7-10700K", 8},
	{"i5-10400", 6},
	{"Ryzen 9 5900X", 12},
	{"i7-12700H", 14},
	{"Ryzen 5 3600", 6},
	{"i5-9400F", 6},
	{"i7-9750H", 6},
	{"Ryzen 7 3700X", 8},
	{"i9-12900K", 16},
	{"i5-12600K", 10},
}

var fingerprintTimezones = []string{
	"UTC", "America/New_York", "America/Chicago", "America/Los_Angeles",
	"Europe/London", "Europe/Berlin", "Europe/Paris", "Asia/Shanghai",
	"Asia/Tokyo", "Asia/Singapore", "Asia/Kolkata", "Australia/Sydney",
	"America/Sao_Paulo", "Europe/Moscow", "Africa/Johannesburg",
}

// FingerprintProfile is the human-readable part of the recorded device.
type FingerprintProfile struct {
	CPUModel  string `json:"cpu_model"`
	CPUCores  int    `json:"cpu_cores"`
	MemoryGiB int    `json:"memory_gib"`
	Timezone  string `json:"timezone"`
}

// DetectionState is everything the gateway remembers about one upstream key's
// client identity. Deadlines use absolute times so state survives restarts.
type DetectionState struct {
	Fingerprint   string             `json:"fingerprint"`
	Profile       FingerprintProfile `json:"profile"`
	MachineIDHash string             `json:"machine_id_hash"`
	MACHashes     []string           `json:"mac_hashes"`
	OSUserHash    string             `json:"os_user_hash"`
	HostnameHash  string             `json:"hostname_hash"`
	GitEmailHash  string             `json:"git_email_hash"`

	FingerprintRefreshAt time.Time `json:"fingerprint_refresh_at"`
	SessionID            string    `json:"session_id"`
	SessionExpiresAt     time.Time `json:"session_expires_at"`
	BaseURL              string    `json:"base_url"`

	// Recorded reports whether the fingerprint/lifecycle handshake has been
	// attempted for this state. It is persisted so a restart does not re-fire
	// the handshake inside the refresh window.
	Recorded bool `json:"recorded"`
}

type detectionFileFormat struct {
	Accounts map[string]DetectionState `json:"accounts"`
}

// DetectionStore owns the in-memory detection state and its persistence. All
// methods are safe for concurrent use.
type DetectionStore struct {
	mu       sync.Mutex
	path     string
	accounts map[string]DetectionState

	// now and randInt are injectable so jitter/TTL behavior is testable.
	now     func() time.Time
	randInt func(n int) int
}

// loadDetection reads detection.json. A missing file is a normal first start;
// a corrupt one is reported and rebuilt rather than aborting startup.
func loadDetection(path string) *DetectionStore {
	store := &DetectionStore{
		path:     path,
		accounts: map[string]DetectionState{},
		now:      time.Now,
		randInt:  secureRandInt,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return store
	}
	var file detectionFileFormat
	if err := json.Unmarshal(data, &file); err != nil {
		log.Printf("[WARN] detection state %s is corrupt, rebuilding: %v", path, err)
		return store
	}
	for id, state := range file.Accounts {
		store.accounts[id] = state
	}
	return store
}

func secureRandInt(n int) int {
	if n <= 1 {
		return 0
	}
	value, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(value.Int64())
}

func (s *DetectionStore) newStateLocked(baseURL string, now time.Time) DetectionState {
	cpu := fingerprintCPUs[s.randInt(len(fingerprintCPUs))]
	memory := fingerprintMemoryGiB[s.randInt(len(fingerprintMemoryGiB))]
	timezone := fingerprintTimezones[s.randInt(len(fingerprintTimezones))]
	macCount := 2 + s.randInt(4)

	state := DetectionState{
		Profile:       FingerprintProfile{CPUModel: cpu.Model, CPUCores: cpu.Cores, MemoryGiB: memory, Timezone: timezone},
		MachineIDHash: randomHash(),
		OSUserHash:    randomHash(),
		HostnameHash:  randomHash(),
		GitEmailHash:  randomHash(),
		BaseURL:       baseURL,
	}
	for i := 0; i < macCount; i++ {
		state.MACHashes = append(state.MACHashes, randomHash())
	}
	state.Fingerprint = computeThumbmark(state)
	state.SessionID = newDetectionSessionID()
	state.SessionExpiresAt = now.Add(detectionSessionTTL + s.jitter(detectionSessionJitter))
	state.FingerprintRefreshAt = now.Add(detectionFingerprintRefresh + s.jitter(detectionFingerprintJitter))
	return state
}

func (s *DetectionStore) jitter(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	return time.Duration(s.randInt(int(limit)))
}

func randomHash() string {
	value, err := randomHex(32)
	if err != nil {
		// crypto/rand failure is unrecoverable for identity generation.
		panic(err)
	}
	return value
}

func newDetectionSessionID() string {
	value, err := randomHex(16)
	if err != nil {
		panic(err)
	}
	return "sess_" + value
}

// computeThumbmark mirrors the reference hash input and order exactly:
// machineIdHash, all macHashes, osUserHash, hostnameHash, gitEmailHash,
// platform, osRelease, cpu model, cores, memory. Timezone, arch, runtime,
// isContainer and collectorVersion are deliberately excluded.
func computeThumbmark(state DetectionState) string {
	parts := []string{state.MachineIDHash}
	parts = append(parts, state.MACHashes...)
	parts = append(parts,
		state.OSUserHash,
		state.HostnameHash,
		state.GitEmailHash,
		detectionPlatform,
		detectionOSRelease,
		state.Profile.CPUModel,
		strconv.Itoa(state.Profile.CPUCores),
		strconv.Itoa(state.Profile.MemoryGiB),
	)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// Ensure returns the account's detection state and whether a (re-)recording is
// due. A new account, a changed base_url, an expired session and a due
// fingerprint refresh all request a handshake.
func (s *DetectionStore) Ensure(accountID, baseURL string) (DetectionState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	state, ok := s.accounts[accountID]
	if !ok || state.BaseURL != baseURL {
		state = s.newStateLocked(baseURL, now)
		s.accounts[accountID] = state
		s.saveLocked()
		return state, true
	}
	if !now.Before(state.SessionExpiresAt) {
		state.SessionID = newDetectionSessionID()
		state.SessionExpiresAt = now.Add(detectionSessionTTL + s.jitter(detectionSessionJitter))
		state.Recorded = false
		s.accounts[accountID] = state
		s.saveLocked()
		return state, true
	}
	if !state.Recorded || !now.Before(state.FingerprintRefreshAt) {
		return state, true
	}
	return state, false
}

// MarkHandshake records that the handshake completed (or was attempted). The
// reference advances the refresh deadline even when the request failed, so a
// failed handshake is not retried on every completion.
func (s *DetectionStore) MarkHandshake(accountID, baseURL string) (DetectionState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.accounts[accountID]
	if !ok || state.BaseURL != baseURL {
		return DetectionState{}, false
	}
	state.FingerprintRefreshAt = s.now().Add(detectionFingerprintRefresh + s.jitter(detectionFingerprintJitter))
	state.Recorded = true
	s.accounts[accountID] = state
	s.saveLocked()
	return state, true
}

// SessionID returns the current per-key session, rotating it when expired.
// It satisfies SessionStore so request metadata can fall back to it.
func (s *DetectionStore) SessionID(accountID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.accounts[accountID]
	if !ok {
		return ""
	}
	now := s.now()
	if !now.Before(state.SessionExpiresAt) {
		state.SessionID = newDetectionSessionID()
		state.SessionExpiresAt = now.Add(detectionSessionTTL + s.jitter(detectionSessionJitter))
		// A rotated session needs a fresh fingerprint handshake.
		state.Recorded = false
		s.accounts[accountID] = state
		s.saveLocked()
	}
	return state.SessionID
}

// State returns a copy of an account's detection state.
func (s *DetectionStore) State(accountID string) (DetectionState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.accounts[accountID]
	return state, ok
}

// Snapshot copies every entry for the admin API.
func (s *DetectionStore) Snapshot() map[string]DetectionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]DetectionState, len(s.accounts))
	for id, state := range s.accounts {
		out[id] = state
	}
	return out
}

// Forget drops an account's state. Used when a key is rotated away or removed.
func (s *DetectionStore) Forget(accountID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[accountID]; !ok {
		return
	}
	delete(s.accounts, accountID)
	s.saveLocked()
}

// ReRecord generates a fresh fingerprint (same account, new device profile).
func (s *DetectionStore) ReRecord(accountID, baseURL string) (DetectionState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.accounts[accountID]
	if !ok || state.BaseURL != baseURL {
		state = s.newStateLocked(baseURL, s.now())
		s.accounts[accountID] = state
		s.saveLocked()
		return state, true
	}
	state = s.regenerateFingerprintLocked(state)
	state.Recorded = false
	s.accounts[accountID] = state
	s.saveLocked()
	return state, true
}

// NewSession rotates the per-key session without touching the fingerprint.
func (s *DetectionStore) NewSession(accountID, baseURL string) (DetectionState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	state, ok := s.accounts[accountID]
	if !ok || state.BaseURL != baseURL {
		state = s.newStateLocked(baseURL, now)
		s.accounts[accountID] = state
		s.saveLocked()
		return state, true
	}
	state.SessionID = newDetectionSessionID()
	state.SessionExpiresAt = now.Add(detectionSessionTTL + s.jitter(detectionSessionJitter))
	s.accounts[accountID] = state
	s.saveLocked()
	return state, true
}

// MarkRecorded records that a handshake was completed out of band (admin
// actions), without changing the session.
func (s *DetectionStore) MarkRecorded(accountID, baseURL string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.accounts[accountID]
	if !ok || state.BaseURL != baseURL {
		return
	}
	state.Recorded = true
	s.accounts[accountID] = state
	s.saveLocked()
}

func (s *DetectionStore) regenerateFingerprintLocked(state DetectionState) DetectionState {
	cpu := fingerprintCPUs[s.randInt(len(fingerprintCPUs))]
	memory := fingerprintMemoryGiB[s.randInt(len(fingerprintMemoryGiB))]
	timezone := fingerprintTimezones[s.randInt(len(fingerprintTimezones))]
	state.Profile = FingerprintProfile{CPUModel: cpu.Model, CPUCores: cpu.Cores, MemoryGiB: memory, Timezone: timezone}
	state.MachineIDHash = randomHash()
	state.OSUserHash = randomHash()
	state.HostnameHash = randomHash()
	state.GitEmailHash = randomHash()
	state.MACHashes = nil
	for i := 0; i < 2+s.randInt(4); i++ {
		state.MACHashes = append(state.MACHashes, randomHash())
	}
	state.Fingerprint = computeThumbmark(state)
	state.FingerprintRefreshAt = s.now().Add(detectionFingerprintRefresh + s.jitter(detectionFingerprintJitter))
	return state
}

// saveLocked writes detection.json atomically (tmp + rename).
func (s *DetectionStore) saveLocked() {
	if s.path == "" {
		return
	}
	file := detectionFileFormat{Accounts: s.accounts}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		log.Printf("[WARN] encode detection state failed: %v", err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("[WARN] write detection state failed: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("[WARN] persist detection state failed: %v", err)
	}
}

// ===== handshake payloads (Phase 1 confirms the exact field names) =====

type fingerprintPayload struct {
	MachineIDHash    string   `json:"machineIdHash"`
	MACHashes        []string `json:"macHashes"`
	OSUserHash       string   `json:"osUserHash"`
	HostnameHash     string   `json:"hostnameHash"`
	GitEmailHash     string   `json:"gitEmailHash"`
	Platform         string   `json:"platform"`
	Arch             string   `json:"arch"`
	OSRelease        string   `json:"osRelease"`
	IsContainer      bool     `json:"isContainer"`
	Runtime          string   `json:"runtime"`
	CollectorVersion int      `json:"collectorVersion"`
	Thumbmark        string   `json:"thumbmark"`
	CPUModel         string   `json:"cpuModel"`
	CPUCores         int      `json:"cpuCores"`
	MemoryGiB        int      `json:"memoryGiB"`
	Timezone         string   `json:"timezone"`
}

type lifecyclePayload struct {
	Event    string `json:"event"`
	Metadata struct {
		SessionID  string `json:"sessionId"`
		CLIVersion string `json:"cliVersion"`
		Mode       string `json:"mode"`
		OS         string `json:"os"`
	} `json:"metadata"`
}

func fingerprintPayloadFrom(state DetectionState) fingerprintPayload {
	return fingerprintPayload{
		MachineIDHash:    state.MachineIDHash,
		MACHashes:        state.MACHashes,
		OSUserHash:       state.OSUserHash,
		HostnameHash:     state.HostnameHash,
		GitEmailHash:     state.GitEmailHash,
		Platform:         detectionPlatform,
		Arch:             detectionArch,
		OSRelease:        detectionOSRelease,
		IsContainer:      false,
		Runtime:          detectionRuntime,
		CollectorVersion: collectorVersion,
		Thumbmark:        state.Fingerprint,
		CPUModel:         state.Profile.CPUModel,
		CPUCores:         state.Profile.CPUCores,
		MemoryGiB:        state.Profile.MemoryGiB,
		Timezone:         state.Profile.Timezone,
	}
}

// lifecyclePayloadFrom uses a fresh random session id per the reference: the
// lifecycle event proves a CLI session exists, it is not the 12h session.
func lifecyclePayloadFrom(state DetectionState, cliVersion string) lifecyclePayload {
	var payload lifecyclePayload
	payload.Event = "cli_session_exists"
	payload.Metadata.SessionID = "sess_" + mustRandomHex(8)
	payload.Metadata.CLIVersion = cliVersion
	payload.Metadata.Mode = "interactive"
	payload.Metadata.OS = detectionPlatform + "-" + detectionArch
	return payload
}

func mustRandomHex(n int) string {
	value, err := randomHex(n)
	if err != nil {
		panic(err)
	}
	return value
}

// FingerprintShort is the display form for the WebUI: first and last eight
// characters, never the full hash.
func FingerprintShort(fingerprint string) string {
	if len(fingerprint) <= 20 {
		return fingerprint
	}
	return fingerprint[:8] + "…" + fingerprint[len(fingerprint)-8:]
}

func detectionTimeString(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
