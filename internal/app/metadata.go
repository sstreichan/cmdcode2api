package app

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strings"
)

// CLI header names. They live here so the request path has exactly one place
// that knows the upstream's expected metadata.
const (
	headerCLIVersion     = "x-command-code-version"
	headerCLIEnvironment = "x-cli-environment"
	headerCoFlag         = "x-co-flag"
	headerTasteLearning  = "x-taste-learning"
	headerSessionID      = "x-session-id"
	headerProjectSlug    = "x-project-slug"
	headerTraceparent    = "traceparent"
	headerZDR            = "x-cmd-zdr"
)

// cliEnvironmentHeader is the value the official CLI sends in
// x-cli-environment (distinct from config.environment, which carries the
// Node/OS string).
const cliEnvironmentHeader = "production"

// SessionStore exposes the gateway's own per-key session IDs. The detection
// store (AD-3) implements it; a nil store simply yields no fallback session.
type SessionStore interface {
	SessionID(accountID string) string
}

// CLIRequestMetadata is the full set of CLI-compatible request metadata. Apply
// is the only place CC headers may be set.
type CLIRequestMetadata struct {
	Version       string
	Environment   string
	SessionID     string
	ProjectSlug   string
	Traceparent   string
	CoFlag        bool
	TasteLearning bool
	ZDREnabled    bool
}

// Apply writes the metadata for /alpha/generate. Content-Type is included so
// callers cannot forget it.
func (m CLIRequestMetadata) Apply(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerCLIVersion, m.Version)
	req.Header.Set(headerCLIEnvironment, m.Environment)
	req.Header.Set(headerCoFlag, boolString(m.CoFlag))
	req.Header.Set(headerTasteLearning, boolString(m.TasteLearning))
	if m.Traceparent != "" {
		req.Header.Set(headerTraceparent, m.Traceparent)
	}
	if m.SessionID != "" {
		req.Header.Set(headerSessionID, m.SessionID)
	}
	if m.ProjectSlug != "" {
		req.Header.Set(headerProjectSlug, m.ProjectSlug)
	}
	if m.ZDREnabled {
		req.Header.Set(headerZDR, "1")
	}
}

// ApplyHandshake writes the reduced metadata set the fingerprint and lifecycle
// endpoints receive: version + environment (+ ZDR), but no traceparent,
// session id or project slug.
func (m CLIRequestMetadata) ApplyHandshake(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerCLIVersion, m.Version)
	req.Header.Set(headerCLIEnvironment, m.Environment)
	if m.ZDREnabled {
		req.Header.Set(headerZDR, "1")
	}
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// randomHexSource is injectable so the traceparent failure path is testable.
var randomHexSource = randomHex

// newTraceparent builds a fresh W3C trace context for one request. IDs are
// drawn from crypto/rand, matching the reference's per-request behavior.
func newTraceparent() (string, error) {
	traceID, err := randomHexSource(16) // 32 hex characters
	if err != nil {
		return "", err
	}
	spanID, err := randomHexSource(8) // 16 hex characters
	if err != nil {
		return "", err
	}
	return "00-" + traceID + "-" + spanID + "-01", nil
}

// projectSlugFromSession derives the CLI-compatible project slug from a
// session id. Hashing keeps working directories, hostnames and usernames out
// of the value.
func projectSlugFromSession(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cmdcode2api/project/" + sessionID))
	return "cc-" + hex.EncodeToString(sum[:6])
}

// resolveSessionID picks the session id the upstream sees. The reference order
// is: inbound x-session-id, x-claude-code-session-id, session_id, then a
// prompt_cache_key of at least 8 characters, then the gateway's own per-key
// session.
func resolveSessionID(header http.Header, promptCacheKey, perKeySession string) string {
	if header != nil {
		for _, name := range []string{headerSessionID, "x-claude-code-session-id", "session_id"} {
			if value := strings.TrimSpace(header.Get(name)); value != "" {
				return value
			}
		}
	}
	if key := strings.TrimSpace(promptCacheKey); len(key) >= 8 {
		return key
	}
	return perKeySession
}

// zdrEnabled reports whether zero-data-retention routing is requested either
// by configuration/environment or by the inbound client.
func zdrEnabled(inbound http.Header) bool {
	if value, ok := os.LookupEnv("CMD_ZDR"); ok && truthyEnv(value) {
		return true
	}
	if inbound != nil && strings.TrimSpace(inbound.Get(headerZDR)) == "1" {
		return true
	}
	return false
}

func truthyEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// sessionFor returns the gateway's own per-key session for an account. AD-3
// fills this from the persisted detection state; empty means the fallback
// chain has nothing else to offer.
func (c *CCClient) sessionFor(account *Account) string {
	if c.sessions == nil || account == nil {
		return ""
	}
	return c.sessions.SessionID(account.ID)
}

// newRequestMetadata assembles the per-attempt metadata for a completion.
func (c *CCClient) newRequestMetadata(inbound http.Header, promptCacheKey, perKeySession string) CLIRequestMetadata {
	sessionID := resolveSessionID(inbound, promptCacheKey, perKeySession)
	traceparent, err := newTraceparent()
	if err != nil {
		// A missing trace is not worth failing the request over.
		log.Printf("[WARN] generate traceparent failed: %v", err)
	}
	return CLIRequestMetadata{
		Version:       c.cliVersion(),
		Environment:   cliEnvironmentHeader,
		SessionID:     sessionID,
		ProjectSlug:   projectSlugFromSession(sessionID),
		Traceparent:   traceparent,
		CoFlag:        false,
		TasteLearning: false,
		ZDREnabled:    zdrEnabled(inbound),
	}
}
