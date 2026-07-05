package main

import (
	"net/http"
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
