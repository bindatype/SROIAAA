package agent

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromEnvRequiresAuthToken(t *testing.T) {
	t.Setenv("SROIAAA_AUTH_TOKEN", "")
	t.Setenv("SROIAAA_AUTH_TOKENS", "")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected error when auth token env vars are unset")
	}
	if !strings.Contains(err.Error(), "auth token") {
		t.Fatalf("expected auth token error, got %v", err)
	}
}

func TestLoadConfigFromEnvLoadsDistinctAuthTokens(t *testing.T) {
	t.Setenv("SROIAAA_AUTH_TOKEN", "primary-token")
	t.Setenv("SROIAAA_AUTH_TOKENS", "rotated-token, primary-token , canary-token")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	want := []string{"primary-token", "rotated-token", "canary-token"}
	if !reflect.DeepEqual(cfg.AuthTokens, want) {
		t.Fatalf("expected auth tokens %v, got %v", want, cfg.AuthTokens)
	}
}

func TestLoadConfigFromEnvUsesHardenedHTTPDefaults(t *testing.T) {
	t.Setenv("SROIAAA_AUTH_TOKEN", "test-token")
	t.Setenv("SROIAAA_BIND_ADDR", "")
	t.Setenv("SROIAAA_MAX_REQUEST_BYTES", "")
	t.Setenv("SROIAAA_READ_HEADER_TIMEOUT", "")
	t.Setenv("SROIAAA_READ_TIMEOUT", "")
	t.Setenv("SROIAAA_WRITE_TIMEOUT", "")
	t.Setenv("SROIAAA_IDLE_TIMEOUT", "")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.BindAddr != "127.0.0.1:8080" {
		t.Fatalf("expected loopback bind, got %q", cfg.BindAddr)
	}
	if cfg.MaxRequestBytes != 65536 {
		t.Fatalf("expected 65536 max request bytes, got %d", cfg.MaxRequestBytes)
	}
	if cfg.ReadHeaderTimeout != 5*time.Second || cfg.ReadTimeout != 15*time.Second ||
		cfg.WriteTimeout != 30*time.Second || cfg.IdleTimeout != 60*time.Second {
		t.Fatalf("unexpected HTTP timeouts: %+v", cfg)
	}
}

func TestLoadConfigFromEnvLoadsHTTPOverrides(t *testing.T) {
	t.Setenv("SROIAAA_AUTH_TOKEN", "test-token")
	t.Setenv("SROIAAA_BIND_ADDR", "[::]:18081")
	t.Setenv("SROIAAA_MAX_REQUEST_BYTES", "4096")
	t.Setenv("SROIAAA_READ_HEADER_TIMEOUT", "2s")
	t.Setenv("SROIAAA_READ_TIMEOUT", "3s")
	t.Setenv("SROIAAA_WRITE_TIMEOUT", "4s")
	t.Setenv("SROIAAA_IDLE_TIMEOUT", "5s")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.BindAddr != "[::]:18081" || cfg.MaxRequestBytes != 4096 {
		t.Fatalf("unexpected HTTP overrides: %+v", cfg)
	}
	if cfg.ReadHeaderTimeout != 2*time.Second || cfg.ReadTimeout != 3*time.Second ||
		cfg.WriteTimeout != 4*time.Second || cfg.IdleTimeout != 5*time.Second {
		t.Fatalf("unexpected timeout overrides: %+v", cfg)
	}
}
