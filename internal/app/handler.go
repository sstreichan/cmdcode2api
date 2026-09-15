package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var debugMode bool

// errZeroOutputHandled stops the stream callback once the zero-output guard
// has already produced its response (or error frame).
var errZeroOutputHandled = errors.New("zero-output guard handled")

func handleChatCompletions(cc *CCClient, cfg *Config, usage *UsageTracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, int64(maxChatRequestBytes))

		var req ChatRequest
		if cfg.Debug {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				writeError(w, 400, "invalid_request_error", "bad request body: "+err.Error())
				return
			}
			log.Printf("%s %s %s", colorize("[DEBUG]", ansiDim), colorize(">> body", ansiGreen), colorize(redactJSONBody(bodyBytes), ansiCyan))
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				// Close rather than reuse: the unread remainder cannot be drained
				// once MaxBytesReader has stopped reading.
				w.Header().Set("Connection", "close")
				writeError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")
				return
			}
			writeError(w, 400, "invalid_request_error", "bad request body: "+err.Error())
			return
		}

		if req.Model == "" {
			writeError(w, 400, "invalid_request_error", "model is required")
			return
		}
		if isModelExcluded(req.Model, cfg.Excludes()) {
			writeError(w, 404, "invalid_request_error", fmt.Sprintf("model %q is not available", req.Model))
			return
		}
		if len(req.Messages) == 0 {
			writeError(w, 400, "invalid_request_error", "messages is required")
			return
		}

		resp, acct, err := cc.SendWithHeaders(r.Context(), &req, r.Header)
		if err != nil {
			var invalid *invalidRequestError
			if errors.As(err, &invalid) {
				writeError(w, http.StatusBadRequest, "invalid_request_error", invalid.Error())
				return
			}
			var upstreamErr *upstreamAPIError
			if errors.As(err, &upstreamErr) {
				log.Printf("%s cc request failed: status=%d type=%s code=%s message=%s",
					colorize("[ERROR]", ansiRed), upstreamErr.Status, upstreamErr.Type, upstreamErr.Code,
					redactText(upstreamErr.Message))
				if upstreamErr.RetryAfter != "" {
					w.Header().Set("Retry-After", upstreamErr.RetryAfter)
				}
				if upstreamErr.RequestID != "" {
					w.Header().Set("x-request-id", upstreamErr.RequestID)
				}
				writeErrorWithCode(w, upstreamErr.Status, upstreamErr.Type, upstreamErr.Code, upstreamErr.Message)
				return
			}
			log.Printf("%s cc request failed: %s", colorize("[ERROR]", ansiRed), redactError(err))
			writeError(w, http.StatusBadGateway, "server_error", "upstream error: "+redactText(err.Error()))
			return
		}

		if req.Stream {
			includeUsage := req.StreamOptions != nil && req.StreamOptions.IncludeUsage
			handleStreamWithAccount(w, resp, req.Model, usage.RecorderFor(acct, clientKeyIDFrom(r.Context())), cfg, includeUsage, acct)
		} else {
			handleNonStreamWithAccount(w, resp, req.Model, usage.RecorderFor(acct, clientKeyIDFrom(r.Context())), cfg, acct)
		}
		if err := usage.save(); err != nil {
			log.Printf("%s save usage failed: %v", colorize("[ERROR]", ansiRed), err)
		}
	}
}

func handleStream(w http.ResponseWriter, resp *http.Response, model string, usage *UsageTracker, cfg *Config) {
	handleStreamWithOptions(w, resp, model, usage, cfg, false)
}

func handleStreamWithOptions(w http.ResponseWriter, resp *http.Response, model string, usage usageRecorder, cfg *Config, includeUsage bool) {
	handleStreamWithAccount(w, resp, model, usage, cfg, includeUsage, nil)
}

func handleStreamWithAccount(w http.ResponseWriter, resp *http.Response, model string, usage usageRecorder, cfg *Config, includeUsage bool, account *Account) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "server_error", "streaming not supported")
		return
	}
	if streamIdleTimeout > 0 && resp.Body != nil {
		resp.Body = newIdleBody(resp.Body, streamIdleTimeout)
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	streamID := genStreamID()
	created := time.Now().Unix()
	firstText := true
	var done bool          // [DONE] has been written; nothing more may be emitted
	var finishing bool     // finishStream is running its final flush
	var wroteAny bool      // any SSE frame has been flushed (response committed)
	var zeroOutput429 bool // guard fired before the first frame, so a real 429 is possible

	writeChunk := func(chunk ChatStreamChunk) {
		wroteAny = true
		writeSSE(w, flusher, chunk)
	}

	normalizer := newCCEventNormalizer()
	var collectedToolCalls toolCallDeduper

	emitContent := func(content string, reasoning bool) {
		if content == "" || done {
			// Once [DONE] is written the stream is closed; anything more would
			// land after it where no OpenAI client will read it. The final flush
			// runs with finishing=true but done=false, so it is still allowed.
			return
		}
		delta := StreamDelta{}
		if reasoning {
			delta.ReasoningContent = content
		} else {
			delta.Content = content
		}
		if firstText {
			delta.Role = "assistant"
			firstText = false
		}
		writeChunk(ChatStreamChunk{
			ID:      streamID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   model,
			Choices: []StreamChoice{{
				Index: 0,
				Delta: delta,
			}},
		})
	}

	collectToolCall := func(tc ToolCall) error {
		if err := validateToolCall(tc); err != nil {
			return err
		}
		collectedToolCalls.Add(tc)
		return nil
	}

	emitCollectedToolCalls := func() {
		for index := range collectedToolCalls.kept {
			tc := &collectedToolCalls.kept[index]
			delta := StreamDelta{ToolCalls: []StreamToolCall{{
				Index:    index,
				ID:       tc.ID,
				Type:     tc.Type,
				Function: &tc.Function,
			}}}
			if firstText {
				delta.Role = "assistant"
				firstText = false
			}
			writeChunk(ChatStreamChunk{
				ID:      streamID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []StreamChoice{{Index: 0, Delta: delta}},
			})
		}
	}

	// finishStream is the commit point: validated authoritative calls can now be
	// emitted exactly once. Provisional tool-input events never reach this set.
	finishStream := func(reason string, usageInfo Usage, truncated bool) error {
		if done || finishing {
			return nil
		}
		finishing = true

		hasToolCalls := len(collectedToolCalls.kept) > 0
		if reason == "tool_calls" && !hasToolCalls {
			return fmt.Errorf("finish reason tool_calls contained no valid tool calls")
		}
		emitCollectedToolCalls()
		finish := resolveFinishReason(reason, hasToolCalls, truncated)
		writeChunk(ChatStreamChunk{
			ID:      streamID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   model,
			Choices: []StreamChoice{{
				Index:        0,
				Delta:        StreamDelta{},
				FinishReason: &finish,
			}},
		})
		if includeUsage {
			writeChunk(ChatStreamChunk{
				ID:      streamID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []StreamChoice{},
				Usage:   &usageInfo,
			})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		done = true
		if debugMode {
			log.Printf("%s %s", colorize("[DEBUG]", ansiDim), colorize(">> [DONE]", ansiGreen))
		}
		flusher.Flush()
		return nil
	}

	failStream := func(code, message string) {
		if done {
			return
		}
		writeSSEError(w, flusher, code, message)
		fmt.Fprint(w, "data: [DONE]\n\n")
		done = true
		if debugMode {
			log.Printf("%s %s", colorize("[DEBUG]", ansiDim), colorize(">> [DONE]", ansiGreen))
		}
		flusher.Flush()
	}

	// failStreamNoDone emits an error frame and closes the connection without
	// [DONE], matching the reference for a timeout after the first frame.
	failStreamNoDone := func(code, message string) {
		if done {
			return
		}
		writeSSEError(w, flusher, code, message)
		done = true
		flusher.Flush()
	}

	endKind, err := parseStreamEvents(resp, func(ev CCStreamEvent) error {
		if cfg.Debug {
			log.Printf("%s %s event type=%s", colorize("[DEBUG]", ansiDim), colorize("<< cc", ansiCyan), ev.Type)
		}
		events, err := normalizer.Consume(ev)
		if err != nil {
			return err
		}
		for _, event := range events {
			switch event.kind {
			case normalizedText:
				emitContent(event.text, false)
			case normalizedReasoning:
				emitContent(event.text, true)
			case normalizedToolCall:
				if event.toolCall != nil {
					if err := collectToolCall(*event.toolCall); err != nil {
						return err
					}
				}
			case normalizedReasoningEnd, normalizedTextEnd:
				// End markers carry no content; text and reasoning deltas are
				// forwarded immediately and are never interpreted as tool syntax.
			case normalizedFinish:
				if normalizer.UsageSeen() && event.usage.CompletionTokens == 0 {
					// Strict zero-output guard, matching the reference: always an
					// error, never a 200 with an empty completion.
					if !wroteAny {
						zeroOutput429 = true
						return errZeroOutputHandled
					}
					failStream("zero_output", "Empty response from upstream (zero output tokens)")
					return errZeroOutputHandled
				}
				if err := finishStream(event.finishReason, event.usage, event.truncated); err != nil {
					return err
				}
			}
		}
		return nil
	})

	if errors.Is(err, errZeroOutputHandled) {
		promptTokens, completionTokens, cacheRead, cacheWrite := normalizer.Usage()
		if zeroOutput429 {
			w.Header().Set("Retry-After", "10")
			writeError(w, http.StatusTooManyRequests, "rate_limit_error", "Empty response from upstream (zero output tokens)")
		}
		recordPartialUsage(usage, promptTokens, completionTokens, cacheRead, cacheWrite)
		logZeroOutputFailure(account)
		return
	}

	if err != nil {
		if isIdleTimeout(err) {
			recordTimeout()
			message := timeoutErrorMessage()
			if !wroteAny {
				// Nothing has been flushed yet, so a real 429 is still possible.
				w.Header().Set("Retry-After", "5")
				writeError(w, http.StatusTooManyRequests, "rate_limit_error", message)
			} else {
				failStreamNoDone("upstream_timeout", message)
			}
			return
		}
		log.Printf("%s stream parse failed: %s", colorize("[ERROR]", ansiRed), redactError(err))
		failStream("upstream_stream_error", "upstream stream error: "+err.Error())
	} else if !done {
		message := "upstream connection closed before a finish event"
		if endKind == streamEndDone {
			message = "upstream sent [DONE] before a finish event"
		}
		log.Printf("%s %s", colorize("[ERROR]", ansiRed), redactText(message))
		failStream("upstream_stream_incomplete", message)
	} else {
		resetTimeoutCounter()
	}

	promptTokens, completionTokens, cacheRead, cacheWrite := normalizer.Usage()
	usage.Record(promptTokens, completionTokens, cacheRead, cacheWrite)
}

func handleNonStream(w http.ResponseWriter, resp *http.Response, model string, usage usageRecorder, cfg *Config) {
	handleNonStreamWithAccount(w, resp, model, usage, cfg, nil)
}

func handleNonStreamWithAccount(w http.ResponseWriter, resp *http.Response, model string, usage usageRecorder, cfg *Config, account *Account) {
	if nonStreamIdleTimeout > 0 && resp.Body != nil {
		resp.Body = newIdleBody(resp.Body, nonStreamIdleTimeout)
	}
	msg := Message{Role: "assistant"}
	var toolCalls toolCallDeduper
	normalizer := newCCEventNormalizer()
	var textContent strings.Builder
	var reasoningContent strings.Builder
	var finishReason string
	var truncated bool
	addToolCall := func(call ToolCall) error {
		if err := validateToolCall(call); err != nil {
			return err
		}
		toolCalls.Add(call)
		return nil
	}

	endKind, err := parseStreamEvents(resp, func(ev CCStreamEvent) error {
		if cfg.Debug {
			log.Printf("%s %s event type=%s", colorize("[DEBUG]", ansiDim), colorize("<< cc", ansiCyan), ev.Type)
		}
		events, err := normalizer.Consume(ev)
		if err != nil {
			return err
		}
		for _, event := range events {
			switch event.kind {
			case normalizedText:
				textContent.WriteString(event.text)
			case normalizedReasoning:
				reasoningContent.WriteString(event.text)
			case normalizedToolCall:
				if event.toolCall != nil {
					if err := addToolCall(*event.toolCall); err != nil {
						return err
					}
				}
			case normalizedFinish:
				finishReason = event.finishReason
				truncated = event.truncated
			}
		}
		return nil
	})

	if err != nil {
		if isIdleTimeout(err) {
			recordTimeout()
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusTooManyRequests, "rate_limit_error", timeoutErrorMessage())
			return
		}
		log.Printf("%s non-stream parse failed: %s", colorize("[ERROR]", ansiRed), redactError(err))
		writeErrorWithCode(w, http.StatusBadGateway, "server_error", "upstream_stream_error", "upstream stream error: "+err.Error())
		return
	}
	if !normalizer.finished {
		message := "upstream connection closed before a finish event"
		if endKind == streamEndDone {
			message = "upstream sent [DONE] before a finish event"
		}
		log.Printf("%s %s", colorize("[ERROR]", ansiRed), redactText(message))
		writeErrorWithCode(w, http.StatusBadGateway, "server_error", "upstream_stream_incomplete", message)
		return
	}

	visibleText := textContent.String()
	reasoningText := reasoningContent.String()

	msg.Content = TextContent(visibleText)
	msg.ToolCalls = toolCalls.kept
	if finishReason == "tool_calls" && len(msg.ToolCalls) == 0 {
		writeErrorWithCode(w, http.StatusBadGateway, "server_error", "invalid_tool_call", "finish reason tool_calls contained no valid tool calls")
		return
	}
	finishReason = resolveFinishReason(finishReason, len(msg.ToolCalls) > 0, truncated)
	if reasoningText != "" {
		msg.ReasoningContent = reasoningText
	}
	promptTokens, completionTokens, cacheRead, cacheWrite := normalizer.FinalUsage()
	if normalizer.UsageSeen() && completionTokens == 0 {
		// Strict zero-output guard: never deliver an empty 200 completion.
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "rate_limit_error", "Empty response from upstream (zero output tokens)")
		recordPartialUsage(usage, promptTokens, completionTokens, cacheRead, cacheWrite)
		logZeroOutputFailure(account)
		return
	}
	usage.Record(promptTokens, completionTokens, cacheRead, cacheWrite)
	resetTimeoutCounter()

	res := ChatResponse{
		ID:      genStreamID(),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []Choice{{
			Index:        0,
			Message:      msg,
			FinishReason: finishReason,
		}},
		Usage: normalizer.FinalUsageInfo(),
	}

	if cfg.Debug {
		raw, _ := json.Marshal(res)
		log.Printf("%s %s %s", colorize("[DEBUG]", ansiDim), colorize(">> response", ansiGreen), colorize(redactJSONBody(raw), ansiCyan))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleModels(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		excludes := cfg.Excludes()
		filtered := make([]ModelInfo, 0, len(modelCatalog))
		for _, m := range modelCatalog {
			if !isModelExcluded(m.ID, excludes) {
				filtered = append(filtered, m)
			}
		}
		json.NewEncoder(w).Encode(ModelList{Object: "list", Data: filtered})
	}
}

// ====================== helpers ======================

func writeError(w http.ResponseWriter, status int, typ, msg string) {
	writeErrorWithCode(w, status, typ, "", msg)
}

func writeErrorWithCode(w http.ResponseWriter, status int, typ, code, msg string) {
	if debugMode {
		log.Printf("%s %s %d %s: %s", colorize("[DEBUG]", ansiDim), colorize(">> error", ansiRed), status, typ, redactText(msg))
	}
	errorBody := map[string]any{
		"message": msg,
		"type":    typ,
		"param":   nil,
	}
	if code != "" {
		errorBody["code"] = code
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": errorBody})
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, chunk ChatStreamChunk) {
	data, _ := json.Marshal(chunk)
	if debugMode {
		log.Printf("%s %s %s", colorize("[DEBUG]", ansiDim), colorize(">> sse", ansiGreen), colorize(redactJSONBody(data), ansiCyan))
	}
	writeDownstream(w, flusher, fmt.Sprintf("data: %s\n\n", data))
}

// writeDownstream writes and flushes one SSE payload. net/http's Write already
// applies backpressure (it blocks while the client's socket buffer is full), so
// the optional deadline is the only thing layered on top: when enabled, a
// stalled reader is disconnected and the upstream is torn down with it.
func writeDownstream(w http.ResponseWriter, flusher http.Flusher, payload string) {
	if clientDrainTimeout > 0 {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(clientDrainTimeout))
	}
	if _, err := io.WriteString(w, payload); err != nil {
		return
	}
	flusher.Flush()
}

func writeSSEError(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	payload := map[string]any{"error": map[string]any{
		"message": message,
		"type":    "server_error",
		"code":    code,
		"param":   nil,
	}}
	data, _ := json.Marshal(payload)
	if debugMode {
		log.Printf("%s %s %s", colorize("[DEBUG]", ansiDim), colorize(">> sse error", ansiRed), colorize(redactJSONBody(data), ansiCyan))
	}
	writeDownstream(w, flusher, fmt.Sprintf("data: %s\n\n", data))
}

func streamEventText(ev CCStreamEvent) string {
	if ev.Text != "" {
		return ev.Text
	}
	return ev.Delta
}

// resolveFinishReason picks the OpenAI finish_reason for a completed turn.
//
// "tool_calls" tells the client the assistant produced a complete set of
// validated structured calls. A length finish always wins because an upstream
// output cap means the turn is incomplete.
func resolveFinishReason(upstream string, hasToolCalls, truncated bool) string {
	if truncated {
		return "length"
	}
	if upstream == "content_filter" {
		return "content_filter"
	}
	if hasToolCalls {
		return "tool_calls"
	}
	return upstream
}

func normalizeFinishReason(reason string) (string, error) {
	switch strings.TrimSpace(reason) {
	case "stop", "end", "end_turn":
		return "stop", nil
	case "tool-calls", "tool_calls", "tool_use", "function_call":
		return "tool_calls", nil
	case "max_tokens", "max_output_tokens", "length":
		return "length", nil
	case "content_filter":
		return "content_filter", nil
	case "":
		return "", fmt.Errorf("finish event missing finish reason")
	default:
		return "", fmt.Errorf("unsupported finish reason %q", reason)
	}
}

func genStreamID() string {
	id, err := randomHex(18)
	if err != nil {
		panic(err)
	}
	return "chatcmpl-" + id
}
