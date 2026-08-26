package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilitiesEndpoint(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestFilesystemListAllowsWorkspaceRoot(t *testing.T) {
	handler, tempDir := newTestHandler(t)

	body := `{
		"operation": "filesystem.list",
		"target": {"path": "` + filepath.ToSlash(filepath.Join(tempDir, "workspace")) + `"},
		"params": {"max_entries": 10}
	}`

	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"entries"`) {
		t.Fatalf("expected entries in response, got %s", rec.Body.String())
	}
}

func TestFilesystemReadBlocksTraversalOutsideAllowedRoot(t *testing.T) {
	handler, tempDir := newTestHandler(t)

	body := `{
		"operation": "filesystem.read",
		"target": {"path": "` + filepath.ToSlash(filepath.Join(tempDir, "outside.txt")) + `"},
		"params": {"max_bytes": 10}
	}`

	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestFilesystemReadClampsExcessiveRead(t *testing.T) {
	handler, tempDir := newTestHandler(t)

	body := `{
		"operation": "filesystem.read",
		"target": {"path": "` + filepath.ToSlash(filepath.Join(tempDir, "workspace", "sample.txt")) + `"},
		"params": {"max_bytes": 999999}
	}`

	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var payload ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload.Status != "ok" {
		t.Fatalf("expected ok, got %s", payload.Status)
	}
}

func TestMalformedJSONRejected(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/operations", bytes.NewBufferString(`{"operation":`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestProcessListUsesConfiguredProcRoot(t *testing.T) {
	handler, _ := newTestHandler(t)

	body := `{"operation": "process.list"}`
	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"count"`) {
		t.Fatalf("expected count in response, got %s", rec.Body.String())
	}
}

func newTestHandler(t *testing.T) (http.Handler, string) {
	t.Helper()

	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	procRoot := filepath.Join(root, "proc")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(procRoot, "100"), 0o755); err != nil {
		t.Fatalf("mkdir proc pid: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sample.txt"), []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.txt"), []byte("blocked"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	status := "Name:\ttestproc\nState:\tS (sleeping)\nPPid:\t1\n"
	if err := os.WriteFile(filepath.Join(procRoot, "100", "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("write proc status: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "100", "cmdline"), []byte("testproc\x00--flag\x00"), 0o644); err != nil {
		t.Fatalf("write proc cmdline: %v", err)
	}

	cfg := Config{
		BindAddr:          ":0",
		AllowedRoots:      []string{workspace},
		ProcRoot:          procRoot,
		MaxReadBytes:      16,
		MaxTailBytes:      16,
		MaxListEntries:    8,
		MaxProcessEntries: 8,
		AuditPath:         filepath.Join(root, "audit.log"),
	}
	auditor, err := NewAuditor(cfg.AuditPath)
	if err != nil {
		t.Fatalf("new auditor: %v", err)
	}
	service := NewService(cfg, auditor)
	return NewHandler(service, cfg), root
}

func performJSONRequest(t *testing.T, handler http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/operations", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
