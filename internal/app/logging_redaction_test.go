package app

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactKeyShapes(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "ccgw-0123456789abcdef0123456789abcdef01234567", want: "ccgw-…4567"},
		{in: "user_testkey_1234567890", want: "user_…7890"},
		{in: "sk-abcdefghijklmnop", want: "sk-…mnop"},
		{in: "short", want: "*****"},
		{in: "", want: ""},
	}
	for _, tt := range tests {
		if got := redactKey(tt.in); got != tt.want {
			t.Errorf("redactKey(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if tt.in != "" && strings.Contains(redactKey(tt.in), tt.in) {
			t.Errorf("redactKey(%q) leaked the full value", tt.in)
		}
	}
}

func TestRedactErrorMasksKeyPatterns(t *testing.T) {
	err := &upstreamAPIError{
		Status:  401,
		Type:    "authentication_error",
		Code:    "invalid_api_key",
		Message: "invalid key user_testkey_1234567890 (Bearer sk-abcdefghijklmnop) for ccgw-0123456789abcdef0123456789abcdef01234567",
	}
	got := redactError(err)
	for _, leak := range []string{"user_testkey_1234567890", "sk-abcdefghijklmnop", "ccgw-0123456789abcdef0123456789abcdef01234567"} {
		if strings.Contains(got, leak) {
			t.Fatalf("redactError leaked %q in %q", leak, got)
		}
	}
}

func TestRedactJSONBodyMasksSensitiveKeys(t *testing.T) {
	body := []byte(`{"api_key":"user_testkey_1234567890","password":"hunter2","nested":{"token":"tok_abcdefghijkl"},"model":"m","messages":[]}`)
	out := redactJSONBody(body)
	for _, leak := range []string{"user_testkey_1234567890", "hunter2", "tok_abcdefghijkl"} {
		if strings.Contains(out, leak) {
			t.Fatalf("redactJSONBody leaked %q in %s", leak, out)
		}
	}
	// Non-sensitive structure must survive so debugging stays useful.
	if !strings.Contains(out, `"model":"m"`) {
		t.Fatalf("redactJSONBody dropped non-sensitive data: %s", out)
	}
	// A key nested inside an array must be masked too.
	nested := redactJSONBody([]byte(`{"items":[{"api_key":"user_abc123456789"}]}`))
	if strings.Contains(nested, "user_abc123456789") {
		t.Fatalf("redactJSONBody leaked a nested key: %s", nested)
	}
}

func TestRedactJSONBodyFallsBackForInvalidJSON(t *testing.T) {
	out := redactJSONBody([]byte(`api_key=user_testkey_1234567890&x=1`))
	if strings.Contains(out, "user_testkey_1234567890") {
		t.Fatalf("redactJSONBody leaked a key from a non-JSON body: %s", out)
	}
}

func TestRedactHeaderOnlyMasksCredentials(t *testing.T) {
	if got := redactHeader("Authorization", "Bearer user_testkey_1234567890"); strings.Contains(got, "user_testkey_1234567890") {
		t.Fatalf("Authorization header leaked: %q", got)
	}
	if got := redactHeader("x-api-key", "user_testkey_1234567890"); strings.Contains(got, "user_testkey_1234567890") {
		t.Fatalf("x-api-key header leaked: %q", got)
	}
	if got := redactHeader("Content-Type", "application/json"); got != "application/json" {
		t.Fatalf("non-sensitive header was altered: %q", got)
	}
}

// captureLogs redirects the standard logger for the duration of fn.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	previousFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(previous)
		log.SetFlags(previousFlags)
	})
	fn()
	return buf.String()
}

func TestDebugLoggingNeverLeaksAPIKeyInBodiesOrErrors(t *testing.T) {
	const secret = "user_testkey_1234567890"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"message":"rejected key `+secret+`","code":"invalid_api_key"}}`)
	}))
	defer upstream.Close()

	cc := NewCCClient(secret, upstream.URL)
	cfg := &Config{Debug: true}
	usage := &UsageTracker{}
	handler := handleChatCompletions(cc, cfg, usage)

	previousDebug := debugMode
	debugMode = true
	t.Cleanup(func() { debugMode = previousDebug })

	body, _ := json.Marshal(ChatRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: TextContent("hi " + secret)}},
	})

	logs := captureLogs(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+secret)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	})

	if strings.Contains(logs, secret) {
		t.Fatalf("logs leaked the full key:\n%s", logs)
	}
	if strings.Contains(logs, "Bearer "+secret) {
		t.Fatalf("logs leaked the bearer value:\n%s", logs)
	}
	if strings.Contains(logs, "sk-") {
		t.Fatalf("logs leaked an sk- pattern:\n%s", logs)
	}
	if !strings.Contains(logs, "user_…7890") {
		t.Fatalf("logs did not carry a redacted key form:\n%s", logs)
	}
}

func TestErrorLogsContainNoStackTraces(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"message":"boom"}`)
	}))
	defer upstream.Close()

	cc := NewCCClient("user_testkey_1234567890", upstream.URL)
	cfg := &Config{}
	usage := &UsageTracker{}
	handler := handleChatCompletions(cc, cfg, usage)

	body, _ := json.Marshal(ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: TextContent("hi")}}})
	logs := captureLogs(t, func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
	})
	if strings.Contains(logs, ".go:") {
		t.Fatalf("error logs contain a stack trace:\n%s", logs)
	}
}

// Gate: no log call may interpolate credentials or raw bodies.
func TestNoLogCallEmitsRawCredentials(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for lineNo, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "log.") {
				continue
			}
			for _, forbidden := range []string{"%+v", "Authorization", "x-api-key", "string(bodyBytes)"} {
				if strings.Contains(line, forbidden) {
					t.Errorf("%s:%d log call emits %s: %s", name, lineNo+1, forbidden, strings.TrimSpace(line))
				}
			}
		}
	}
}
