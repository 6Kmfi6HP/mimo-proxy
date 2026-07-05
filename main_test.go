package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestConfigLoadsSocks5(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("socks5: socks5h://100.74.21.88:7890\n"), &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	if cfg.Socks5 != "socks5h://100.74.21.88:7890" {
		t.Fatalf("Config.Socks5 = %q, want socks5h://100.74.21.88:7890", cfg.Socks5)
	}
}

func TestSocks5URLFromConfigEnvOverridesConfig(t *testing.T) {
	t.Setenv("MIMO_SOCKS5", "socks5h://100.74.21.88:7890")

	got := socks5URLFromConfig(Config{Socks5: "socks5://127.0.0.1:7890"})
	if got != "socks5h://100.74.21.88:7890" {
		t.Fatalf("socks5URLFromConfig returned %q, want env override", got)
	}
}

func TestResetUpstreamConnectionRebuildsTransport(t *testing.T) {
	oldClient := httpClient
	oldURL := socks5URL
	t.Cleanup(func() {
		httpClient = oldClient
		socks5URL = oldURL
	})

	socks5URL = "socks5h://127.0.0.1:7890"
	if err := configureHTTPClient(socks5URL); err != nil {
		t.Fatalf("configureHTTPClient: %v", err)
	}
	first := httpClient.Transport

	resetUpstreamConnection("risk_control")

	second := httpClient.Transport
	if first == second {
		t.Fatal("expected new transport after reset")
	}
	transport, ok := second.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", second)
	}
	if !transport.DisableKeepAlives {
		t.Fatal("expected DisableKeepAlives on proxy transport")
	}
}

func TestConfigureHTTPClientUsesSocks5HDialer(t *testing.T) {
	oldClient := httpClient
	t.Cleanup(func() { httpClient = oldClient })

	if err := configureHTTPClient("socks5h://100.74.21.88:7890"); err != nil {
		t.Fatalf("configureHTTPClient: %v", err)
	}

	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("httpClient.Transport = %T, want *http.Transport", httpClient.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("transport.DialContext is nil; SOCKS5 proxy is not wired")
	}
	if httpClient.Timeout != requestTimeout+30*time.Second {
		t.Fatalf("httpClient.Timeout = %v, want %v", httpClient.Timeout, requestTimeout+30*time.Second)
	}
}

func TestGetJwtExpiredCacheBootstrapFailReturnsError(t *testing.T) {
	// Point bootstrap to a port that will fail fast.
	oldURL := bootstrapURL
	bootstrapURL = "http://127.0.0.1:1/nope"
	t.Cleanup(func() { bootstrapURL = oldURL })

	jwtMu.Lock()
	jwtCached = &jwtEntry{jwt: "old-token", exp: time.Now().UnixMilli() - 1000}
	jwtMu.Unlock()
	t.Cleanup(func() {
		jwtMu.Lock()
		jwtCached = nil
		jwtMu.Unlock()
	})

	_, err := getJwt(context.Background())
	if err == nil {
		t.Fatal("getJwt should error when cache is expired and bootstrap fails")
	}
}

func TestCallUpstreamInvalidTokenRetryOnceWithNewJwt(t *testing.T) {
	var (
		mu             sync.Mutex
		authHeaders    []string
		bootstrapCalls int
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if strings.Contains(r.URL.Path, "bootstrap") {
			bootstrapCalls++
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"jwt": fmt.Sprintf("jwt-%d", bootstrapCalls)})
			return
		}
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		shouldInvalid := len(authHeaders) == 1
		mu.Unlock()

		if shouldInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Token"})
			return
		}
		w.Write([]byte(`ok`))
	}))
	defer ts.Close()

	oldBootstrap, oldChat := bootstrapURL, chatURL
	bootstrapURL = ts.URL + "/bootstrap"
	chatURL = ts.URL + "/chat"
	t.Cleanup(func() { bootstrapURL, chatURL = oldBootstrap, oldChat })

	// Clear any cached JWT from prior tests.
	jwtMu.Lock()
	jwtCached = nil
	jwtMu.Unlock()

	resp, err := callUpstream(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("callUpstream: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(authHeaders) != 2 {
		t.Fatalf("expected 2 upstream attempts, got %d auth headers: %v", len(authHeaders), authHeaders)
	}
	if authHeaders[0] != "Bearer jwt-1" {
		t.Fatalf("first attempt: got %q, want %q", authHeaders[0], "Bearer jwt-1")
	}
	if authHeaders[1] != "Bearer jwt-2" {
		t.Fatalf("second (retry) attempt: got %q, want %q", authHeaders[1], "Bearer jwt-2")
	}
}

func TestBootstrapUsesDistinctFingerprintEachCall(t *testing.T) {
	fingerprintMu.Lock()
	fingerprintVal = ""
	fingerprintMu.Unlock()

	var clients []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Client string `json:"client"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		clients = append(clients, req.Client)
		json.NewEncoder(w).Encode(map[string]string{"jwt": "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.x"})
	}))
	defer ts.Close()

	old := bootstrapURL
	bootstrapURL = ts.URL
	t.Cleanup(func() { bootstrapURL = old })

	for i := 0; i < 3; i++ {
		if _, err := bootstrap(context.Background()); err != nil {
			t.Fatalf("bootstrap %d: %v", i, err)
		}
	}
	if len(clients) != 3 {
		t.Fatalf("expected 3 bootstrap clients, got %d", len(clients))
	}
	for i := 1; i < len(clients); i++ {
		if clients[i] == clients[i-1] {
			t.Fatalf("bootstrap %d reused fingerprint %q", i+1, clients[i])
		}
	}
}

func TestCallUpstreamRotatesFingerprintOnPersistentError(t *testing.T) {
	var (
		mu             sync.Mutex
		authHeaders    []string
		bootstrapPings []string // recorded bootstrap client values
		bootstrapCalls int
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(r.URL.Path, "bootstrap") {
			bootstrapCalls++
			// Decode and record the client fingerprint.
			var req struct {
				Client string `json:"client"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			bootstrapPings = append(bootstrapPings, req.Client)
			json.NewEncoder(w).Encode(map[string]string{"jwt": fmt.Sprintf("jwt-%d", bootstrapCalls)})
			return
		}
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		// 1st call: Invalid Token → retry (step 0).
		// 2nd call: still fails with risk_control (step 1 re-bootstrap).
		// 3rd call: accept (step 2).
		switch len(authHeaders) {
		case 1:
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid Token"})
		case 2:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "risk_control"})
		default:
			w.Write([]byte(`ok`))
		}
	}))
	defer ts.Close()

	oldBootstrap, oldChat := bootstrapURL, chatURL
	bootstrapURL = ts.URL + "/bootstrap"
	chatURL = ts.URL + "/chat"
	t.Cleanup(func() { bootstrapURL, chatURL = oldBootstrap, oldChat })

	jwtMu.Lock()
	jwtCached = nil
	jwtMu.Unlock()

	fingerprintMu.Lock()
	fingerprintVal = ""
	fingerprintMu.Unlock()

	resp, err := callUpstream(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("callUpstream: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(authHeaders) != 3 {
		t.Fatalf("expected 3 upstream attempts, got %d: %v", len(authHeaders), authHeaders)
	}

	if len(bootstrapPings) < 3 {
		t.Fatalf("expected 3 bootstraps, got %d: %v", len(bootstrapPings), bootstrapPings)
	}
	for i := 1; i < len(bootstrapPings); i++ {
		if bootstrapPings[i] == bootstrapPings[i-1] {
			t.Fatalf("bootstrap %d reused fingerprint %q", i+1, bootstrapPings[i])
		}
	}
}

func TestCallUpstreamRetriesOnHighFrequencyBlock(t *testing.T) {
	var (
		mu             sync.Mutex
		authHeaders    []string
		bootstrapCalls int
		bootstrapPings []string
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(r.URL.Path, "bootstrap") {
			bootstrapCalls++
			var req struct {
				Client string `json:"client"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			bootstrapPings = append(bootstrapPings, req.Client)
			json.NewEncoder(w).Encode(map[string]string{"jwt": fmt.Sprintf("jwt-%d", bootstrapCalls)})
			return
		}
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		// 1st call: high-frequency block → should retry with fingerprint rotation.
		// 2nd call: succeeds.
		switch len(authHeaders) {
		case 1:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Detected high-frequency non-compliant requests from you. Please consciously comply with the platform usage agreement."})
		default:
			w.Write([]byte(`ok`))
		}
	}))
	defer ts.Close()

	oldBootstrap, oldChat := bootstrapURL, chatURL
	bootstrapURL = ts.URL + "/bootstrap"
	chatURL = ts.URL + "/chat"
	t.Cleanup(func() { bootstrapURL, chatURL = oldBootstrap, oldChat })

	jwtMu.Lock()
	jwtCached = nil
	jwtMu.Unlock()

	fingerprintMu.Lock()
	fingerprintVal = ""
	fingerprintMu.Unlock()

	resp, err := callUpstream(context.Background(), []byte(`{}`))
	if err != nil {
		t.Fatalf("callUpstream: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if len(authHeaders) != 2 {
		t.Fatalf("expected 2 upstream attempts, got %d", len(authHeaders))
	}

	if bootstrapCalls != 2 {
		t.Fatalf("expected 2 bootstrap calls, got %d", bootstrapCalls)
	}
	if len(bootstrapPings) != 2 || bootstrapPings[0] == bootstrapPings[1] {
		t.Fatalf("expected distinct bootstrap fingerprints, got %v", bootstrapPings)
	}
}
