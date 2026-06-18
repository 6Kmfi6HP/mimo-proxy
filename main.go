package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// --- config ---

const (
	defaultPort         = "5000"
	defaultBaseURL      = "https://api.xiaomimimo.com"
	jwtRefreshBuffer    = 5 * time.Minute
	jwtDefaultTTL       = 50 * time.Minute
	maxBodyBytes   = 32 * 1024 * 1024
	requestTimeout = 5 * time.Minute
	shutdownGracePeriod = 25 * time.Second
	// antiAbuseMarker is required in the system message to pass upstream's anti-abuse check.
	antiAbuseMarker = "You are MiMoCode, an interactive CLI tool that helps users with software engineering tasks."
)

var (
	port         string
	bootstrapURL string
	chatURL      string
	apiKey       string
	httpClient   = &http.Client{Timeout: requestTimeout + 30*time.Second}
)

// Config represents the configuration file structure.
type Config struct {
	Port     string `yaml:"port"`
	APIKey   string `yaml:"api_key"`
	BaseURL  string `yaml:"base_url"`
}

// loadConfig reads the configuration from config.yaml.
func loadConfig() Config {
	cfg := Config{
		Port:    defaultPort,
		BaseURL: defaultBaseURL,
	}

	data, err := os.ReadFile("config.yaml")
	if err != nil {
		// Config file is optional, use defaults.
		return cfg
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("warning: failed to parse config.yaml: %v", err)
		return cfg
	}

	// Apply defaults for empty fields.
	if cfg.Port == "" {
		cfg.Port = defaultPort
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}

	return cfg
}

// --- fingerprint ---

var (
	fingerprintOnce sync.Once
	fingerprintVal  string
)

func getFingerprint() string {
	fingerprintOnce.Do(func() {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "unknown-host"
		}
		platform := runtime.GOOS
		arch := runtime.GOARCH
		username := "unknown-user"
		if u, err := osUserInfo(); err == nil {
			username = u
		}
		seed := fmt.Sprintf("%s|%s|%s|%s|%s",
			hostname, platform, arch, username, randomUUID())
		h := sha256.Sum256([]byte(seed))
		fingerprintVal = fmt.Sprintf("%x", h)
	})
	return fingerprintVal
}

func osUserInfo() (string, error) {
	// os/user requires cgo on some platforms; use env vars as fallback.
	if u := os.Getenv("USER"); u != "" {
		return u, nil
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u, nil
	}
	return "", fmt.Errorf("cannot determine username")
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x%08x%08x%08x", b[0:4], b[4:8], b[8:12], b[12:16])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// --- jwt cache ---

type jwtEntry struct {
	jwt string
	exp int64 // unix millis
}

var (
	jwtMu     sync.Mutex
	jwtCached *jwtEntry
)

func parseExp(jwt string) int64 {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return time.Now().UnixMilli() + jwtDefaultTTL.Milliseconds()
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Now().UnixMilli() + jwtDefaultTTL.Milliseconds()
	}
	var payload struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(payloadBytes, &payload) != nil {
		return time.Now().UnixMilli() + jwtDefaultTTL.Milliseconds()
	}
	if payload.Exp > 0 {
		return payload.Exp * 1000 // JWT exp is in seconds, convert to millis
	}
	return time.Now().UnixMilli() + jwtDefaultTTL.Milliseconds()
}

func bootstrap(ctx context.Context) (*jwtEntry, error) {
	payload := map[string]string{"client": getFingerprint()}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", bootstrapURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mimocode/1.0.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		text, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("mimo bootstrap %d: %s", resp.StatusCode, string(text))
	}

	var data struct {
		Jwt string `json:"jwt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("mimo bootstrap: %w", err)
	}
	if data.Jwt == "" {
		return nil, fmt.Errorf("mimo bootstrap: missing jwt")
	}
	return &jwtEntry{jwt: data.Jwt, exp: parseExp(data.Jwt)}, nil
}

// getJwt returns the cached JWT. The background refresher keeps it fresh.
func getJwt(ctx context.Context) (string, error) {
	jwtMu.Lock()
	defer jwtMu.Unlock()
	if jwtCached != nil {
		return jwtCached.jwt, nil
	}
	return "", fmt.Errorf("no JWT available")
}

// startJwtRefresher proactively keeps the JWT fresh via a background goroutine.
func startJwtRefresher(ctx context.Context) {
	// Initial fill.
	if entry, err := bootstrap(ctx); err == nil {
		jwtMu.Lock()
		jwtCached = entry
		jwtMu.Unlock()
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jwtMu.Lock()
				needsRefresh := jwtCached == nil || jwtCached.exp-time.Now().UnixMilli() <= jwtRefreshBuffer.Milliseconds()
				jwtMu.Unlock()
				if needsRefresh {
					if entry, err := bootstrap(ctx); err == nil {
						jwtMu.Lock()
						jwtCached = entry
						jwtMu.Unlock()
					}
				}
			}
		}
	}()
}

// --- upstream ---

func upstreamRequest(ctx context.Context, jwt string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", chatURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Mimo-Source", "mimocode-cli-free")
	req.Header.Set("x-session-affinity", "ses_"+randomHex(12))
	req.Header.Set("User-Agent", "mimocode/1.0.0")
	return req, nil
}

func callUpstream(ctx context.Context, body []byte) (*http.Response, error) {
	jwt, err := getJwt(ctx)
	if err != nil {
		return nil, err
	}
	req, err := upstreamRequest(ctx, jwt, body)
	if err != nil {
		return nil, err
	}
	return httpClient.Do(req)
}

// --- http helpers ---

var errBodyTooLarge = fmt.Errorf("request body exceeds %d bytes", maxBodyBytes)

func urlPath(u string) string {
	if i := strings.Index(u, "?"); i != -1 {
		return u[:i]
	}
	return u
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// --- handlers ---

func handleHealth(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":       true,
		"upstream": chatURL,
	})
}

func handleModels(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"object": "list",
		"data": []map[string]interface{}{
			{
				"id":       "mimo-auto",
				"object":   "model",
				"created":  time.Now().Unix(),
				"owned_by": "xiaomimimo",
			},
		},
	})
}

// ensureAntiAbuseMarker ensures the system message contains the anti-abuse marker
// and forces the model to "mimo-auto" (the only supported model).
func ensureAntiAbuseMarker(body []byte) []byte {
	var raw map[string]interface{}
	if json.Unmarshal(body, &raw) != nil {
		return body
	}

	// Force model to mimo-auto.
	raw["model"] = "mimo-auto"

	msgs, ok := raw["messages"].([]interface{})
	if !ok {
		out, _ := json.Marshal(raw)
		return out
	}

	// Check if first message is a system message with the marker.
	hasMarker := false
	if len(msgs) > 0 {
		if msg, ok := msgs[0].(map[string]interface{}); ok && msg["role"] == "system" {
			if text := extractText(msg["content"]); strings.Contains(text, antiAbuseMarker) {
				hasMarker = true
			}
		}
	}

	// Prepend a system message with the marker if missing.
	if !hasMarker {
		sysMsg := map[string]interface{}{
			"role":    "system",
			"content": antiAbuseMarker,
		}
		raw["messages"] = append([]interface{}{sysMsg}, msgs...)
	}

	out, _ := json.Marshal(raw)
	return out
}

func readBody(r *http.Request) ([]byte, error) {
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(bodyBytes) > maxBodyBytes {
		return nil, errBodyTooLarge
	}
	return bodyBytes, nil
}

func readBodyOrErr(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := readBody(r)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, map[string]interface{}{
			"error": map[string]interface{}{
				"message": err.Error(),
				"type":    "invalid_request_error",
			},
		})
		return nil, false
	}
	return body, true
}

func writeProxyError(w http.ResponseWriter, ctx context.Context, err error) {
	status := http.StatusBadGateway
	if ctx.Err() != nil {
		status = 499 // client closed request
	}
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"message": err.Error(),
			"type":    "proxy_error",
		},
	})
}

func handleChat(w http.ResponseWriter, r *http.Request) {
	setCORS(w)

	bodyBytes, ok := readBodyOrErr(w, r)
	if !ok {
		return
	}

	// Ensure anti-abuse system message is present.
	bodyBytes = ensureAntiAbuseMarker(bodyBytes)

	ctx := r.Context()
	resp, err := callUpstream(ctx, bodyBytes)
	if err != nil {
		writeProxyError(w, ctx, err)
		return
	}
	defer resp.Body.Close()

	// Copy headers.
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")

	// Stream the body. Clear write deadline for long-lived SSE connections.
	if flusher, ok := w.(http.Flusher); ok {
		http.NewResponseController(w).SetWriteDeadline(time.Time{})
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 4096)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				if _, writeErr := w.Write(buf[:n]); writeErr != nil {
					return
				}
				flusher.Flush()
			}
			if readErr != nil {
				break
			}
		}
	} else {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// --- anthropic translation ---

func extractUpstreamError(body []byte) string {
	var errResp struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error.Message != "" {
		return errResp.Error.Message
	}
	return string(body)
}

type anthropicMsgReq struct {
	Model         string          `json:"model"`
	Messages      []anthropicMsg  `json:"messages"`
	System        interface{}     `json:"system"`
	MaxTokens     int             `json:"max_tokens"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
	Stream        bool            `json:"stream,omitempty"`
	Tools         []anthropicTool `json:"tools,omitempty"`
	ToolChoice    interface{}     `json:"tool_choice,omitempty"`
	Thinking      *anthropicThinking `json:"thinking,omitempty"`
	Metadata      *anthropicMetadata `json:"metadata,omitempty"`
}

type anthropicThinking struct {
	Type        string `json:"type"`        // "enabled" or "disabled"
	BudgetTokens int   `json:"budget_tokens,omitempty"`
}

type anthropicMetadata struct {
	UserID string `json:"user_id,omitempty"`
}

type anthropicMsg struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"`
}

type anthropicTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema interface{} `json:"input_schema"`
}

// extractImageURL converts an Anthropic image content block to a URL string.
func extractImageURL(b map[string]interface{}) string {
	source, ok := b["source"].(map[string]interface{})
	if !ok {
		return ""
	}
	switch source["type"] {
	case "base64":
		mediaType, _ := source["media_type"].(string)
		data, _ := source["data"].(string)
		if mediaType != "" && data != "" {
			return "data:" + mediaType + ";base64," + data
		}
	case "url":
		if url, _ := source["url"].(string); url != "" {
			return url
		}
	}
	return ""
}

// extractText handles Anthropic's polymorphic content field (string or []contentBlock).
func extractText(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		var sb strings.Builder
		for _, block := range c {
			b, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			if t, _ := b["type"].(string); t == "text" {
				if txt, ok := b["text"].(string); ok {
					sb.WriteString(txt)
				}
			}
		}
		return sb.String()
	}
	return ""
}

func mapFinishReason(r string) string {
	switch r {
	case "stop":
		return "end_turn"
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	}
	return r
}

func anthropicToOpenAI(req anthropicMsgReq) map[string]interface{} {
	oa := map[string]interface{}{
		"model":    "mimo-auto", // Force to the only supported model.
		"messages": []interface{}{},
		"stream":   req.Stream,
	}
	if req.Stream {
		oa["stream_options"] = map[string]interface{}{"include_usage": true}
	}
	if req.MaxTokens > 0 {
		oa["max_tokens"] = req.MaxTokens
	}
	if req.Temperature != nil {
		oa["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		oa["top_p"] = *req.TopP
	}
	if len(req.StopSequences) > 0 {
		oa["stop"] = req.StopSequences
	}
	if len(req.Tools) > 0 {
		tools := make([]interface{}, 0, len(req.Tools))
		for _, t := range req.Tools {
			tools = append(tools, map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name":        t.Name,
					"description": t.Description,
					"parameters":  t.InputSchema,
				},
			})
		}
		oa["tools"] = tools
	}
	if req.ToolChoice != nil {
		oa["tool_choice"] = convertToolChoice(req.ToolChoice)
	}
	if req.Thinking != nil && req.Thinking.Type == "enabled" && req.Thinking.BudgetTokens > 0 {
		oa["thinking_budget"] = req.Thinking.BudgetTokens
	}
	if req.Metadata != nil && req.Metadata.UserID != "" {
		oa["user"] = req.Metadata.UserID
	}

	messages := oa["messages"].([]interface{})

	// system → prepend as system message (ensure anti-abuse marker is present)
	sysText := extractText(req.System)
	if !strings.Contains(sysText, antiAbuseMarker) {
		if sysText != "" {
			sysText = antiAbuseMarker + "\n\n" + sysText
		} else {
			sysText = antiAbuseMarker
		}
	}
	if sysText != "" {
		messages = append(messages, map[string]interface{}{
			"role":    "system",
			"content": sysText,
		})
	}

	for _, m := range req.Messages {
		content := m.Content

		// Anthropic assistant messages may contain tool_use blocks.
		if m.Role == "assistant" {
			if blocks, ok := content.([]interface{}); ok {
				var textParts []string
				var reasoningParts []string
				var toolCalls []interface{}
				for _, block := range blocks {
					b, ok := block.(map[string]interface{})
					if !ok {
						continue
					}
					switch b["type"] {
					case "text":
						if txt, _ := b["text"].(string); txt != "" {
							textParts = append(textParts, txt)
						}
					case "thinking":
						if txt, _ := b["thinking"].(string); txt != "" {
							reasoningParts = append(reasoningParts, txt)
						}
					case "tool_use":
						tc := map[string]interface{}{
							"id":   b["id"],
							"type": "function",
							"function": map[string]interface{}{
								"name":      b["name"],
								"arguments": mustJSON(b["input"]),
							},
						}
						toolCalls = append(toolCalls, tc)
					}
				}
				if len(toolCalls) > 0 || len(reasoningParts) > 0 {
					msg := map[string]interface{}{
						"role": "assistant",
					}
					if len(textParts) > 0 {
						msg["content"] = strings.Join(textParts, "")
					}
					if len(reasoningParts) > 0 {
						msg["reasoning_content"] = strings.Join(reasoningParts, "")
					}
					if len(toolCalls) > 0 {
						msg["tool_calls"] = toolCalls
					}
					messages = append(messages, msg)
					continue
				}
			}
		}

		// Anthropic user messages may contain tool_result blocks.
		if m.Role == "user" {
			if blocks, ok := content.([]interface{}); ok {
				var contentParts []interface{} // text + image_url blocks
				var toolResults []interface{}
				for _, block := range blocks {
					b, ok := block.(map[string]interface{})
					if !ok {
						continue
					}
					switch b["type"] {
					case "text":
						if txt, _ := b["text"].(string); txt != "" {
							contentParts = append(contentParts, map[string]interface{}{
								"type": "text",
								"text": txt,
							})
						}
					case "image":
						if url := extractImageURL(b); url != "" {
							contentParts = append(contentParts, map[string]interface{}{
								"type": "image_url",
								"image_url": map[string]interface{}{
									"url": url,
								},
							})
						}
					case "tool_result":
						resultContent := ""
						if c, ok := b["content"].(string); ok {
							resultContent = c
						} else if blocks2, ok := b["content"].([]interface{}); ok {
							var parts []string
							for _, b2 := range blocks2 {
								if m2, ok := b2.(map[string]interface{}); ok && m2["type"] == "text" {
									parts = append(parts, m2["text"].(string))
								}
							}
							resultContent = strings.Join(parts, "")
						}
						toolResults = append(toolResults, map[string]interface{}{
							"role":       "tool",
							"tool_call_id": b["tool_use_id"],
							"content":    resultContent,
						})
					}
				}
				// Emit content parts as a user message, then tool results.
				if len(contentParts) > 0 {
					if len(contentParts) == 1 {
						// Single text block → use string content.
						if p, ok := contentParts[0].(map[string]interface{}); ok && p["type"] == "text" {
							messages = append(messages, map[string]interface{}{
								"role":    "user",
								"content": p["text"],
							})
						} else {
							messages = append(messages, map[string]interface{}{
								"role":    "user",
								"content": contentParts,
							})
						}
					} else {
						messages = append(messages, map[string]interface{}{
							"role":    "user",
							"content": contentParts,
						})
					}
				}
				for _, tr := range toolResults {
					messages = append(messages, tr)
				}
				continue
			}
		}

		messages = append(messages, map[string]interface{}{
			"role":    m.Role,
			"content": extractText(content),
		})
	}
	oa["messages"] = messages
	return oa
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// convertToolChoice maps Anthropic tool_choice to OpenAI format.
func convertToolChoice(v interface{}) interface{} {
	tc, ok := v.(map[string]interface{})
	if !ok {
		return v
	}
	switch tc["type"] {
	case "auto":
		return "auto"
	case "any":
		return "required"
	case "none":
		return "none"
	case "tool":
		if name, _ := tc["name"].(string); name != "" {
			return map[string]interface{}{
				"type": "function",
				"function": map[string]interface{}{
					"name": name,
				},
			}
		}
		return "auto"
	}
	return "auto"
}

func openaiToAnthropic(openaiBody []byte, model string) map[string]interface{} {
	var oa struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Role             string `json:"role"`
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
				ToolCalls        []struct {
					ID       string `json:"id"`
					Type     string `json:"type"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage *struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(openaiBody, &oa); err != nil {
		// Try to extract upstream error message before giving up.
		var errResp struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		msg := "[upstream response parse error]"
		if json.Unmarshal(openaiBody, &errResp) == nil && errResp.Error.Message != "" {
			msg = errResp.Error.Message
		}
		return map[string]interface{}{
			"id":      "msg_" + randomID(),
			"type":    "message",
			"role":    "assistant",
			"content": []interface{}{map[string]interface{}{"type": "text", "text": msg}},
			"model":   model,
		}
	}

	stopReason := "end_turn"
	if len(oa.Choices) > 0 && oa.Choices[0].FinishReason != nil {
		stopReason = mapFinishReason(*oa.Choices[0].FinishReason)
	}

	role := "assistant"
	var contentBlocks []interface{}
	if len(oa.Choices) > 0 {
		msg := oa.Choices[0].Message
		if msg.Role != "" {
			role = msg.Role
		}
		if msg.ReasoningContent != "" {
			contentBlocks = append(contentBlocks, map[string]interface{}{
				"type":     "thinking",
				"thinking": msg.ReasoningContent,
			})
		}
		if msg.Content != "" {
			contentBlocks = append(contentBlocks, map[string]interface{}{
				"type": "text",
				"text": msg.Content,
			})
		}
		for _, tc := range msg.ToolCalls {
			var input map[string]interface{}
			json.Unmarshal([]byte(tc.Function.Arguments), &input)
			contentBlocks = append(contentBlocks, map[string]interface{}{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Function.Name,
				"input": input,
			})
		}
	}
	if len(contentBlocks) == 0 {
		contentBlocks = []interface{}{map[string]interface{}{"type": "text", "text": ""}}
	}

	resp := map[string]interface{}{
		"id":          "msg_" + randomID(),
		"type":        "message",
		"role":        role,
		"content":     contentBlocks,
		"model":       model,
		"stop_reason": stopReason,
	}
	if oa.Usage != nil {
		resp["usage"] = map[string]interface{}{
			"input_tokens":  oa.Usage.PromptTokens,
			"output_tokens": oa.Usage.CompletionTokens,
		}
	}
	return resp
}

func emitSSE(w io.Writer, flusher http.Flusher, event string, data interface{}) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, jsonBytes); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func translateStream(ctx context.Context, upstream io.Reader, w io.Writer, flusher http.Flusher, model string, inputTokens int) error {
	msgID := "msg_" + randomID()
	var started, stopped bool
	var outputTokens int

	// Block index tracking: sequential, auto-assigned.
	type blockState struct {
		index   int
		blockType string // "thinking", "text", "tool_use"
		closed  bool
		name    string // for tool_use
	}
	var blocks []*blockState
	// Map from OpenAI tool_call index → blockState.
	toolBlocks := map[int]*blockState{}

	allocBlock := func(bt string) *blockState {
		bs := &blockState{index: len(blocks), blockType: bt}
		blocks = append(blocks, bs)
		return bs
	}

	emitMessageStart := func() error {
		return emitSSE(w, flusher, "message_start", map[string]interface{}{
			"type": "message_start",
			"message": map[string]interface{}{
				"id":            msgID,
				"type":          "message",
				"role":          "assistant",
				"content":       []interface{}{},
				"model":         model,
				"stop_reason":   nil,
				"stop_sequence": nil,
				"usage": map[string]int{
					"input_tokens":  inputTokens,
					"output_tokens": 0,
				},
			},
		})
	}
	closeBlock := func(bs *blockState) error {
		if !bs.closed {
			bs.closed = true
			return emitSSE(w, flusher, "content_block_stop", map[string]interface{}{
				"type":  "content_block_stop",
				"index": bs.index,
			})
		}
		return nil
	}
	closeLastOpenBlock := func() error {
		for i := len(blocks) - 1; i >= 0; i-- {
			if !blocks[i].closed {
				return closeBlock(blocks[i])
			}
		}
		return nil
	}
	emitStopEvents := func(stopReason string) error {
		if err := closeLastOpenBlock(); err != nil {
			return err
		}
		if err := emitSSE(w, flusher, "message_delta", map[string]interface{}{
			"type": "message_delta",
			"delta": map[string]interface{}{
				"stop_reason":   stopReason,
				"stop_sequence": nil,
			},
			"usage": map[string]int{
				"output_tokens": outputTokens,
			},
		}); err != nil {
			return err
		}
		return emitSSE(w, flusher, "message_stop", map[string]interface{}{
			"type": "message_stop",
		})
	}

	scanner := bufio.NewScanner(upstream)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			if !started {
				if err := emitMessageStart(); err != nil {
					return err
				}
			}
			if len(blocks) == 0 {
				// No content at all — emit empty text block.
				bs := allocBlock("text")
				if err := emitSSE(w, flusher, "content_block_start", map[string]interface{}{
					"type":          "content_block_start",
					"index":         bs.index,
					"content_block": map[string]interface{}{"type": "text", "text": ""},
				}); err != nil {
					return err
				}
			}
			if !stopped {
				if err := emitStopEvents("end_turn"); err != nil {
					return err
				}
			}
			break
		}

		var chunk struct {
			Choices []struct {
				Delta struct {
					Role             string `json:"role"`
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) == 0 {
			continue
		}
		choice := chunk.Choices[0]

		if !started {
			started = true
			if err := emitMessageStart(); err != nil {
				return err
			}
		}

		// Reasoning/thinking content.
		if choice.Delta.ReasoningContent != "" {
			// Find or create thinking block.
			var thinkingBlock *blockState
			for _, bs := range blocks {
				if bs.blockType == "thinking" && !bs.closed {
					thinkingBlock = bs
					break
				}
			}
			if thinkingBlock == nil {
				thinkingBlock = allocBlock("thinking")
				if err := emitSSE(w, flusher, "content_block_start", map[string]interface{}{
					"type":  "content_block_start",
					"index": thinkingBlock.index,
					"content_block": map[string]interface{}{
						"type":     "thinking",
						"thinking": "",
					},
				}); err != nil {
					return err
				}
			}
			if err := emitSSE(w, flusher, "content_block_delta", map[string]interface{}{
				"type":  "content_block_delta",
				"index": thinkingBlock.index,
				"delta": map[string]interface{}{
					"type":     "thinking_delta",
					"thinking": choice.Delta.ReasoningContent,
				},
			}); err != nil {
				return err
			}
		}

		// Text content.
		if choice.Delta.Content != "" {
			// Close thinking block if still open.
			for _, bs := range blocks {
				if bs.blockType == "thinking" && !bs.closed {
					if err := closeBlock(bs); err != nil {
						return err
					}
				}
			}
			// Find or create text block.
			var textBlock *blockState
			for _, bs := range blocks {
				if bs.blockType == "text" && !bs.closed {
					textBlock = bs
					break
				}
			}
			if textBlock == nil {
				textBlock = allocBlock("text")
				if err := emitSSE(w, flusher, "content_block_start", map[string]interface{}{
					"type":          "content_block_start",
					"index":         textBlock.index,
					"content_block": map[string]interface{}{"type": "text", "text": ""},
				}); err != nil {
					return err
				}
			}
			if err := emitSSE(w, flusher, "content_block_delta", map[string]interface{}{
				"type":  "content_block_delta",
				"index": textBlock.index,
				"delta": map[string]interface{}{
					"type": "text_delta",
					"text": choice.Delta.Content,
				},
			}); err != nil {
				return err
			}
		}

		// Tool calls.
		for _, tc := range choice.Delta.ToolCalls {
			tb, exists := toolBlocks[tc.Index]
			if !exists {
				// Close thinking and text blocks if still open.
				for _, bs := range blocks {
					if (bs.blockType == "thinking" || bs.blockType == "text") && !bs.closed {
						if err := closeBlock(bs); err != nil {
							return err
						}
					}
				}
				tb = allocBlock("tool_use")
				tb.name = tc.Function.Name
				toolBlocks[tc.Index] = tb
				if err := emitSSE(w, flusher, "content_block_start", map[string]interface{}{
					"type":  "content_block_start",
					"index": tb.index,
					"content_block": map[string]interface{}{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  tb.name,
						"input": map[string]interface{}{},
					},
				}); err != nil {
					return err
				}
			}
			if tc.Function.Arguments != "" {
				if err := emitSSE(w, flusher, "content_block_delta", map[string]interface{}{
					"type":  "content_block_delta",
					"index": tb.index,
					"delta": map[string]interface{}{
						"type":         "input_json_delta",
						"partial_json": tc.Function.Arguments,
					},
				}); err != nil {
					return err
				}
			}
		}

		if choice.FinishReason != nil {
			stopped = true
			if chunk.Usage != nil {
				inputTokens = chunk.Usage.PromptTokens
				outputTokens = chunk.Usage.CompletionTokens
			}
			if err := emitStopEvents(mapFinishReason(*choice.FinishReason)); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	setCORS(w)

	bodyBytes, ok := readBodyOrErr(w, r)
	if !ok {
		return
	}

	var req anthropicMsgReq
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": map[string]interface{}{"message": err.Error(), "type": "invalid_request_error"},
		})
		return
	}

	oaReq := anthropicToOpenAI(req)
	oaBody, err := json.Marshal(oaReq)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": map[string]interface{}{"message": err.Error(), "type": "server_error"},
		})
		return
	}

	ctx := r.Context()
	resp, err := callUpstream(ctx, oaBody)
	if err != nil {
		writeProxyError(w, ctx, err)
		return
	}
	defer resp.Body.Close()

	// Count input tokens for streaming metadata.
	inputTokens := countTokens(oaReq)

	if req.Stream {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error": map[string]interface{}{"message": "streaming not supported", "type": "server_error"},
			})
			return
		}

		// If upstream returned an error status, relay it as Anthropic error.
		if resp.StatusCode >= 400 {
			errBody, _ := io.ReadAll(resp.Body)
			writeJSON(w, resp.StatusCode, map[string]interface{}{
				"error": map[string]interface{}{
					"type":    "api_error",
					"message": extractUpstreamError(errBody),
				},
			})
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		http.NewResponseController(w).SetWriteDeadline(time.Time{})
		w.WriteHeader(resp.StatusCode)

		if err := translateStream(ctx, resp.Body, w, flusher, req.Model, inputTokens); err != nil {
			return
		}
		return
	}

	// Non-streaming.
	resBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		writeJSON(w, resp.StatusCode, map[string]interface{}{
			"error": map[string]interface{}{
				"type":    "api_error",
				"message": extractUpstreamError(resBody),
			},
		})
		return
	}

	anthropicResp := openaiToAnthropic(resBody, req.Model)
	writeJSON(w, resp.StatusCode, anthropicResp)
}

// countTokens estimates input tokens from the OpenAI request.
// Uses a rough heuristic: ASCII ≈ 4 chars/token, CJK ≈ 1.5 chars/token.
func countTokens(req map[string]interface{}) int {
	body, _ := json.Marshal(req)
	var ascii, nonASCII int
	for i := 0; i < len(body); i++ {
		if body[i] < 128 {
			ascii++
		} else {
			nonASCII++
		}
	}
	return ascii/4 + nonASCII*2/3
}

// checkAPIKey validates the API key if configured.
func checkAPIKey(w http.ResponseWriter, r *http.Request) bool {
	if apiKey == "" {
		return true // No API key configured, allow all.
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error": map[string]interface{}{
				"message": "missing Authorization header",
				"type":    "authentication_error",
			},
		})
		return false
	}

	// Support "Bearer <key>" format.
	token := strings.TrimPrefix(auth, "Bearer ")
	if token != apiKey {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error": map[string]interface{}{
				"message": "invalid API key",
				"type":    "authentication_error",
			},
		})
		return false
	}

	return true
}

// --- server ---

func main() {
	// Load configuration from config.yaml.
	cfg := loadConfig()

	// Environment variables override config file.
	port = os.Getenv("PORT")
	if port == "" {
		port = cfg.Port
	}
	baseURL := strings.TrimRight(os.Getenv("MIMO_BASE_URL"), "/")
	if baseURL == "" {
		baseURL = cfg.BaseURL
	}
	apiKey = cfg.APIKey

	bootstrapURL = baseURL + "/api/free-ai/bootstrap"
	chatURL = baseURL + "/api/free-ai/openai/chat"

	// Shutdown-aware handler.
	var shuttingDown bool
	var sdMu sync.Mutex

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sdMu.Lock()
		sd := shuttingDown
		sdMu.Unlock()

		if sd && urlPath(r.URL.Path) != "/health" {
			setCORS(w)
			w.Header().Set("Connection", "close")
			writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error": map[string]interface{}{
					"message": "server shutting down",
					"type":    "server_error",
				},
			})
			return
		}

		path := urlPath(r.URL.Path)

		if r.Method == http.MethodOptions {
			setCORS(w)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Health endpoint doesn't require authentication.
		if r.Method == http.MethodGet && path == "/health" {
			handleHealth(w, r)
			return
		}

		// Check API key for all other endpoints.
		if !checkAPIKey(w, r) {
			return
		}

		switch {
		case r.Method == http.MethodGet && (path == "/v1/models" || path == "/models"):
			handleModels(w, r)
		case r.Method == http.MethodPost && (path == "/v1/chat/completions" || path == "/chat/completions"):
			handleChat(w, r)
		case r.Method == http.MethodPost && (path == "/v1/messages" || path == "/messages"):
			handleAnthropicMessages(w, r)
		default:
			setCORS(w)
			writeJSON(w, http.StatusNotFound, map[string]interface{}{
				"error": map[string]interface{}{
					"message": "Not found",
					"type":    "invalid_request_error",
				},
			})
		}
	})

	srv := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      handler,
		ReadTimeout:  requestTimeout,
		WriteTimeout: requestTimeout,
		IdleTimeout:  2 * requestTimeout,
	}

	// Start JWT auto-refresh in background.
	startJwtRefresher(context.Background())

	// Start server in background.
	go func() {
		log.Printf("mimo-proxy listening on http://0.0.0.0:%s", port)
		log.Printf("fingerprint:  %s", getFingerprint())
		log.Printf("forwarding:   POST %s", chatURL)
		if apiKey != "" {
			log.Printf("api_key:      configured")
		} else {
			log.Printf("api_key:      not configured (open access)")
		}
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh

	sdMu.Lock()
	shuttingDown = true
	sdMu.Unlock()

	log.Printf("\n%s received, draining (max %.0fs)...", sig, shutdownGracePeriod.Seconds())

	ctx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
		os.Exit(1)
	}
	log.Println("server stopped")
}
