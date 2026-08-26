package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	BindAddr          string
	AllowedRoots      []string
	ProcRoot          string
	MaxReadBytes      int64
	MaxTailBytes      int64
	MaxListEntries    int
	MaxProcessEntries int
	AuditPath         string
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		BindAddr:          envOrDefault("SROIAAA_BIND_ADDR", ":8080"),
		ProcRoot:          envOrDefault("SROIAAA_PROC_ROOT", "/proc"),
		AuditPath:         envOrDefault("SROIAAA_AUDIT_PATH", "runtime/audit.log"),
		MaxReadBytes:      envInt64("SROIAAA_MAX_READ_BYTES", 65536),
		MaxTailBytes:      envInt64("SROIAAA_MAX_TAIL_BYTES", 65536),
		MaxListEntries:    int(envInt64("SROIAAA_MAX_LIST_ENTRIES", 256)),
		MaxProcessEntries: int(envInt64("SROIAAA_MAX_PROCESS_ENTRIES", 256)),
	}

	roots := strings.Split(envOrDefault("SROIAAA_ALLOWED_ROOTS", "/workspace,/tmp,/var/log/sroiaaa"), ",")
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		if !filepath.IsAbs(root) {
			return Config{}, fmt.Errorf("allowed root must be absolute: %q", root)
		}
		cfg.AllowedRoots = append(cfg.AllowedRoots, filepath.Clean(root))
	}
	if len(cfg.AllowedRoots) == 0 {
		return Config{}, fmt.Errorf("at least one allowed root is required")
	}
	if !filepath.IsAbs(cfg.ProcRoot) {
		return Config{}, fmt.Errorf("proc root must be absolute: %q", cfg.ProcRoot)
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}
