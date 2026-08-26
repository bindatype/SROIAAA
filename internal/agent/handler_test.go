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
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHealthEndpointDoesNotRequireAuth(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestCapabilitiesEndpointRejectsMissingAuth(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("expected WWW-Authenticate header")
	}
}

func TestCapabilitiesEndpointAcceptsRotatedToken(t *testing.T) {
	handler, _ := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.AuthTokens = []string{"primary-token", "rotated-token"}
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer rotated-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
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
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestMultipleJSONValuesRejected(t *testing.T) {
	handler, _ := newTestHandler(t)

	rec := performJSONRequest(t, handler, `{"operation":"host.info"} {"operation":"host.info"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOversizedRequestRejected(t *testing.T) {
	handler, root := newTestHandlerWithConfig(t, func(cfg *Config) {
		cfg.MaxRequestBytes = 48
	})

	body := `{"operation":"host.info","params":{"padding":"` + strings.Repeat("x", 64) + `"}}`
	rec := performJSONRequest(t, handler, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"code":"request_too_large"`) {
		t.Fatalf("expected request_too_large error, got %s", rec.Body.String())
	}
	audit, err := os.ReadFile(filepath.Join(root, "audit.log"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if !strings.Contains(string(audit), `"code":"request_too_large"`) {
		t.Fatalf("expected oversized request audit event, got %s", audit)
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
	return newTestHandlerWithConfig(t, nil)
}

func newTestHandlerWithConfig(t *testing.T, configure func(*Config)) (http.Handler, string) {
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
		AuthTokens:        []string{"test-token"},
		AllowedRoots:      []string{workspace},
		ProcRoot:          procRoot,
		MaxRequestBytes:   1024,
		MaxReadBytes:      16,
		MaxTailBytes:      16,
		MaxListEntries:    8,
		MaxProcessEntries: 8,
		AuditPath:         filepath.Join(root, "audit.log"),
	}
	if configure != nil {
		configure(&cfg)
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
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
