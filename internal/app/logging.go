package app

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiCyan   = "\x1b[36m"
)

type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

type flushStatusRecorder struct {
	*statusRecorder
	flusher http.Flusher
}

func newStatusRecorder(w http.ResponseWriter) (*statusRecorder, http.ResponseWriter) {
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	flusher, ok := w.(http.Flusher)
	if !ok {
		return recorder, recorder
	}
	return recorder, &flushStatusRecorder{statusRecorder: recorder, flusher: flusher}
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += n
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (r *flushStatusRecorder) Flush() {
	r.flusher.Flush()
}

func formatHTTPLog(method, path string, status int, duration time.Duration, remoteAddr string) string {
	return fmt.Sprintf(
		"%s %s %s %s %s %s",
		colorize("[HTTP]", ansiDim),
		colorize(sanitizeLogField(method), methodColor(method)),
		sanitizeLogField(path),
		colorize(fmt.Sprintf("%d", status), statusColor(status)),
		colorize(formatDuration(duration), ansiDim),
		colorize(sanitizeLogField(clientIP(remoteAddr)), ansiDim),
	)
}

func sanitizeLogField(value string) string {
	if value == "" {
		return value
	}
	quoted := strconv.QuoteToASCII(value)
	return strings.Trim(quoted, "\"")
}

func formatDuration(duration time.Duration) string {
	if duration >= time.Second {
		return duration.Round(time.Millisecond).String()
	}
	return duration.Round(time.Microsecond).String()
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	return remoteAddr
}

func colorize(text, color string) string {
	if color == "" || !useColor() {
		return text
	}
	return color + text + ansiReset
}

func useColor() bool {
	_, noColor := os.LookupEnv("NO_COLOR")
	return !noColor
}

// ====== redaction ======
//
// Credentials must never reach a log line in full. The helpers below are the
// only sanctioned way to render keys, headers, error messages and bodies.

var (
	bearerTokenPattern = regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9._~+/=-]+)`)
	secretTokenPattern = regexp.MustCompile(`(?:user_|ccgw-|sk-)[A-Za-z0-9_-]{4,}`)
)

// redactKey renders a credential as a short prefix plus the last four
// characters (ccgw-…a1b2, user_…a1b2). Values too short to mask are fully
// starred.
func redactKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	prefixEnd := 4
	if index := strings.IndexAny(value, "-_"); index >= 0 {
		prefixEnd = index + 1
	}
	if prefixEnd > 6 {
		prefixEnd = 6
	}
	return value[:prefixEnd] + "\u2026" + value[len(value)-4:]
}

// redactText masks any credential-shaped token inside free-form text.
func redactText(text string) string {
	if text == "" {
		return ""
	}
	text = bearerTokenPattern.ReplaceAllStringFunc(text, func(match string) string {
		index := strings.IndexByte(match, ' ')
		if index < 0 {
			return redactKey(match)
		}
		return match[:index+1] + redactKey(match[index+1:])
	})
	return secretTokenPattern.ReplaceAllStringFunc(text, redactKey)
}

// redactError renders an error for logging without credentials or bodies.
func redactError(err error) string {
	if err == nil {
		return ""
	}
	return redactText(err.Error())
}

// redactHeader masks credential-bearing headers and passes everything else
// through unchanged.
func redactHeader(name, value string) string {
	if sensitiveHeaderNames[strings.ToLower(strings.TrimSpace(name))] {
		return redactKey(strings.TrimSpace(strings.TrimPrefix(value, "Bearer ")))
	}
	return value
}

var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"api-key":             true,
	"cookie":              true,
	"set-cookie":          true,
}

// sensitiveJSONKeys list the fields whose values are masked in debug bodies.
var sensitiveJSONKeys = map[string]bool{
	"apikey":        true,
	"api_key":       true,
	"key":           true,
	"token":         true,
	"authorization": true,
	"password":      true,
	"secret":        true,
	"access_token":  true,
	"refresh_token": true,
	"client_secret": true,
}

// redactJSONBody masks sensitive JSON fields and any credential-shaped token,
// so debug logging of a request or response body stays useful but leak-free.
// Non-JSON bodies fall back to text redaction.
func redactJSONBody(raw []byte) string {
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return redactText(string(raw))
	}
	masked, err := json.Marshal(redactJSONValue(decoded))
	if err != nil {
		return redactText(string(raw))
	}
	return redactText(string(masked))
}

func redactJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, entry := range typed {
			if sensitiveJSONKeys[strings.ToLower(key)] {
				typed[key] = maskJSONValue(entry)
				continue
			}
			typed[key] = redactJSONValue(entry)
		}
		return typed
	case []any:
		for i := range typed {
			typed[i] = redactJSONValue(typed[i])
		}
		return typed
	default:
		return value
	}
}

func maskJSONValue(value any) any {
	if text, ok := value.(string); ok {
		return redactKey(text)
	}
	if value == nil {
		return nil
	}
	return "***"
}

func statusColor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return ansiGreen
	case status >= 300 && status < 400:
		return ansiCyan
	case status >= 400 && status < 500:
		return ansiYellow
	case status >= 500:
		return ansiRed
	default:
		return ""
	}
}

func methodColor(method string) string {
	switch method {
	case http.MethodGet:
		return ansiBlue
	case http.MethodPost:
		return ansiGreen
	case http.MethodPut, http.MethodPatch:
		return ansiYellow
	case http.MethodDelete:
		return ansiRed
	default:
		return ansiCyan
	}
}
