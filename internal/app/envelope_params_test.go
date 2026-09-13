package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func convertWith(t *testing.T, req *ChatRequest) CCRequest {
	t.Helper()
	got, err := openAIToCC(req)
	if err != nil {
		t.Fatalf("openAIToCC: %v", err)
	}
	return got
}

func TestOpenAIToCCPassesReasoningEffort(t *testing.T) {
	got := convertWith(t, &ChatRequest{
		Model:           "m",
		Messages:        []Message{{Role: "user", Content: TextContent("hi")}},
		ReasoningEffort: "high",
	})
	if got.Params.ReasoningEffort != "high" {
		t.Fatalf("reasoning_effort = %q, want high", got.Params.ReasoningEffort)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"reasoning_effort":"high"`) {
		t.Fatalf("reasoning_effort missing from wire JSON: %s", encoded)
	}

	// Absent must stay absent so the golden envelope is unchanged.
	without := convertWith(t, &ChatRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: TextContent("hi")}},
	})
	encoded, err = json.Marshal(without)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "reasoning_effort") {
		t.Fatalf("reasoning_effort must be omitted when unset: %s", encoded)
	}

	// The reference forwards every value verbatim; an unexpected value must
	// still be sent rather than silently dropped.
	odd := convertWith(t, &ChatRequest{
		Model:           "m",
		Messages:        []Message{{Role: "user", Content: TextContent("hi")}},
		ReasoningEffort: "ultra",
	})
	encoded, err = json.Marshal(odd)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"reasoning_effort":"ultra"`) {
		t.Fatalf("unexpected reasoning_effort must still pass through: %s", encoded)
	}
}

func TestOpenAIToCCPassesSamplingParams(t *testing.T) {
	temperature := 0.7
	parallel := false
	got := convertWith(t, &ChatRequest{
		Model:             "m",
		Messages:          []Message{{Role: "user", Content: TextContent("hi")}},
		Temperature:       &temperature,
		ParallelToolCalls: &parallel,
	})
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(encoded)
	for _, want := range []string{`"temperature":0.7`, `"parallel_tool_calls":false`} {
		if !strings.Contains(wire, want) {
			t.Errorf("wire JSON missing %s: %s", want, wire)
		}
	}

	// A zero temperature is a real value, not "unset".
	zero := 0.0
	gotZero := convertWith(t, &ChatRequest{
		Model:       "m",
		Messages:    []Message{{Role: "user", Content: TextContent("hi")}},
		Temperature: &zero,
	})
	encoded, err = json.Marshal(gotZero)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"temperature":0`) {
		t.Fatalf("temperature 0 must be sent: %s", encoded)
	}

	// Absent means absent.
	plain := convertWith(t, &ChatRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: TextContent("hi")}},
	})
	encoded, err = json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "temperature") || strings.Contains(string(encoded), "parallel_tool_calls") {
		t.Fatalf("optional params must be omitted when unset: %s", encoded)
	}
}

func TestOpenAIToCCMapsToolChoice(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "auto", raw: `"auto"`, want: `{"type":"auto"}`},
		{name: "none", raw: `"none"`, want: `{"type":"none"}`},
		{name: "required becomes any", raw: `"required"`, want: `{"type":"any"}`},
		{
			name: "function object becomes tool",
			raw:  `{"type":"function","function":{"name":"lookup"}}`,
			want: `{"type":"tool","name":"lookup"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertWith(t, &ChatRequest{
				Model:      "m",
				Messages:   []Message{{Role: "user", Content: TextContent("hi")}},
				ToolChoice: json.RawMessage(tt.raw),
			})
			encoded, err := json.Marshal(got.Params.ToolChoice)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tt.want {
				t.Fatalf("tool_choice = %s, want %s", encoded, tt.want)
			}
		})
	}

	if _, err := openAIToCC(&ChatRequest{
		Model:      "m",
		Messages:   []Message{{Role: "user", Content: TextContent("hi")}},
		ToolChoice: json.RawMessage(`{not-json`),
	}); err == nil {
		t.Fatal("malformed tool_choice must be rejected")
	}
}

func TestOpenAIToCCPassesThroughClientToolChoice(t *testing.T) {
	// A tool_choice object must survive alongside tools.
	got := convertWith(t, &ChatRequest{
		Model:      "m",
		Messages:   []Message{{Role: "user", Content: TextContent("hi")}},
		Tools:      []Tool{{Type: "function", Function: ToolFunction{Name: "lookup"}}},
		ToolChoice: json.RawMessage(`"required"`),
	})
	if got.Params.ToolChoice == nil || got.Params.ToolChoice.Type != "any" {
		t.Fatalf("tool_choice = %#v, want any", got.Params.ToolChoice)
	}
}

func TestOpenAIToCCAddsCacheControlForPromptCacheKey(t *testing.T) {
	got := convertWith(t, &ChatRequest{
		Model: "m",
		Messages: []Message{
			{Role: "user", Content: TextContent("first question")},
			{Role: "assistant", Content: TextContent("answer")},
			{Role: "user", Content: TextContent("second question")},
		},
		PromptCacheKey: "cache-key-123",
	})

	firstUser := got.Params.Messages[0]
	lastPart := firstUser.Content[len(firstUser.Content)-1]
	if lastPart.CacheControl == nil || lastPart.CacheControl.Type != "ephemeral" {
		t.Fatalf("first user message last text part = %#v, want cache_control ephemeral", lastPart)
	}
	// Only the first user message is marked.
	for i, msg := range got.Params.Messages {
		for j, part := range msg.Content {
			if part.CacheControl != nil && !(i == 0 && j == len(msg.Content)-1) {
				t.Fatalf("unexpected cache_control on message %d part %d", i, j)
			}
		}
	}

	// Without a prompt_cache_key nothing is marked.
	plain := convertWith(t, &ChatRequest{
		Model:    "m",
		Messages: []Message{{Role: "user", Content: TextContent("first question")}},
	})
	for _, part := range plain.Params.Messages[0].Content {
		if part.CacheControl != nil {
			t.Fatalf("cache_control must not be added without prompt_cache_key: %#v", part)
		}
	}
}

func TestEnvelopeAdditionsAreAdditive(t *testing.T) {
	// The six CLI envelope fields must still exist exactly once and the new
	// params must not disturb them.
	got := convertWith(t, &ChatRequest{
		Model:           "m",
		Messages:        []Message{{Role: "user", Content: TextContent("hi")}},
		ReasoningEffort: "medium",
	})
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(encoded)
	for _, field := range []string{`"config":`, `"memory":`, `"taste":`, `"skills":`, `"permissionMode":`, `"params":`} {
		if strings.Count(wire, field) != 1 {
			t.Fatalf("envelope field %s appears %d times: %s", field, strings.Count(wire, field), wire)
		}
	}
}

func TestToolChoiceMappingRejectsObjectWithoutName(t *testing.T) {
	got := convertWith(t, &ChatRequest{
		Model:      "m",
		Messages:   []Message{{Role: "user", Content: TextContent("hi")}},
		ToolChoice: json.RawMessage(`{"type":"function","function":{}}`),
	})
	if got.Params.ToolChoice != nil {
		t.Fatalf("tool_choice without a function name must be ignored, got %#v", got.Params.ToolChoice)
	}
}

func TestToolChoiceUnrecognizedStringIsIgnored(t *testing.T) {
	got := convertWith(t, &ChatRequest{
		Model:      "m",
		Messages:   []Message{{Role: "user", Content: TextContent("hi")}},
		ToolChoice: json.RawMessage(`"nonsense"`),
	})
	if got.Params.ToolChoice != nil {
		t.Fatalf("unrecognized tool_choice must be ignored, got %#v", got.Params.ToolChoice)
	}
}

// Guard: an invalid tool_choice must surface as a client error, not a panic.
func TestToolChoiceMalformedIsClientError(t *testing.T) {
	_, err := openAIToCC(&ChatRequest{
		Model:      "m",
		Messages:   []Message{{Role: "user", Content: TextContent("hi")}},
		ToolChoice: json.RawMessage(`123`),
	})
	var invalid *invalidRequestError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want invalidRequestError", err)
	}
}
