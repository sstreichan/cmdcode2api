package app

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

// Gateway robustness limits. Timeouts are vars so tests can inject short
// values instead of waiting; the env overrides exist for operators.
var (
	// maxChatRequestBytes matches the reference's 100 MB body limit.
	maxChatRequestBytes = 100 * 1024 * 1024
	// maxInflightRequests caps concurrent chat requests; 0 disables the cap.
	maxInflightRequests = envInt("CC_MAX_INFLIGHT", 0)
	// streamIdleTimeout is the streaming idle watchdog (reset per upstream
	// chunk). 0 disables it.
	streamIdleTimeout = envDurationMS("CC_STREAM_IDLE_MS", 30*time.Second)
	// nonStreamIdleTimeout is the stream:false buffered-drain idle watchdog.
	nonStreamIdleTimeout = envDurationMS("CC_NONSTREAM_IDLE_MS", 90*time.Second)
	// clientDrainTimeout optionally bounds a stalled downstream write. Off by
	// default: a client blocked on tool execution looks identical to a stall.
	clientDrainTimeout = envDurationMS("CC_CLIENT_DRAIN_TIMEOUT_MS", 0)
)

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value < 0 {
		return fallback
	}
	return value
}

func envDurationMS(name string, fallback time.Duration) time.Duration {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return fallback
	}
	return time.Duration(value) * time.Millisecond
}

// ===== consecutive timeout counter (process-global, like the reference) =====

const timeoutHintThreshold = 3

const (
	timeoutMessage          = "Response timeout - request timed out"
	timeoutReduceContextMsg = "Response timeout - try reducing context length (summarize earlier messages)"
)

var consecutiveTimeouts atomic.Int64

func recordTimeout()       { consecutiveTimeouts.Add(1) }
func resetTimeoutCounter() { consecutiveTimeouts.Store(0) }
func timeoutCount() int64  { return consecutiveTimeouts.Load() }

// timeoutHintFor returns the extra hint appended once the threshold is hit.
func timeoutHintFor() string {
	if consecutiveTimeouts.Load() >= timeoutHintThreshold {
		return timeoutReduceContextMsg
	}
	return ""
}

// timeoutErrorMessage builds the client-facing timeout message.
func timeoutErrorMessage() string {
	if hint := timeoutHintFor(); hint != "" {
		return hint
	}
	return timeoutMessage
}

// ===== in-flight cap =====

func isLivenessPath(path string) bool {
	return path == "/health" || path == "/"
}

// applyInflightLimit rejects concurrent chat requests beyond the configured
// cap with 503 server_busy. Liveness paths never count and never 503.
func applyInflightLimit(next http.Handler) http.Handler {
	var inflight atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maxInflightRequests <= 0 || isLivenessPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if inflight.Add(1) > int64(maxInflightRequests) {
			inflight.Add(-1)
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "server_busy", "server is busy, retry shortly")
			return
		}
		defer inflight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// ===== zero-output usage =====

// zeroOutputUsage nulls input/cache tokens on a zero-output response so the
// client cannot be billed for a prompt the upstream returned nothing for.
func zeroOutputUsage(usage Usage) Usage {
	usage.PromptTokens = 0
	usage.TotalTokens = 0
	usage.PromptTokensDetails = nil
	return usage
}

// logZeroOutputFailure records a zero-output response against the account's
// generic error counter without inventing a new field.
func logZeroOutputFailure(account *Account) {
	if account == nil {
		return
	}
	account.RecordFailure(&upstreamAPIError{
		Status:  http.StatusTooManyRequests,
		Type:    "rate_limit_error",
		Code:    "zero_output",
		Message: "upstream returned zero output tokens",
	})
}

// partialUsageRecorder records tokens without counting the request as a
// success, for zero-output responses.
type partialUsageRecorder interface {
	RecordPartial(prompt, completion, cacheRead, cacheWrite int)
}

func recordPartialUsage(rec usageRecorder, prompt, completion, cacheRead, cacheWrite int) {
	if partial, ok := rec.(partialUsageRecorder); ok {
		partial.RecordPartial(prompt, completion, cacheRead, cacheWrite)
		return
	}
	rec.Record(prompt, completion, cacheRead, cacheWrite)
}

// logRobustnessConfig is called at startup to make the active limits visible.
func logRobustnessConfig() {
	log.Printf("gateway limits: stream_idle=%s nonstream_idle=%s max_inflight=%d body_limit=%dMB drain_timeout_ms=%d",
		streamIdleTimeout, nonStreamIdleTimeout, maxInflightRequests,
		maxChatRequestBytes/(1024*1024), clientDrainTimeout.Milliseconds())
}
