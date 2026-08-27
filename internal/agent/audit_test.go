package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewAuditorUsesPrivateFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	auditor, err := NewAuditor(path)
	if err != nil {
		t.Fatalf("new auditor: %v", err)
	}
	t.Cleanup(func() { _ = auditor.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected audit mode 0600, got %04o", got)
	}
}
