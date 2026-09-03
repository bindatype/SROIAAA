package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maclach/sroiaaa/internal/agent"
	"github.com/maclach/sroiaaa/internal/broker"
)

func TestSROIAAAConnectorExecutesOnlyTheApprovedStep(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "system.log")
	if err := os.WriteFile(logPath, []byte("first line\nlast line\n"), 0o600); err != nil {
		t.Fatalf("write agent fixture: %v", err)
	}
	resolvedLogPath, err := filepath.EvalSymlinks(logPath)
	if err != nil {
		t.Fatalf("resolve agent fixture: %v", err)
	}
	auditor := &recordingAgentAuditor{}
	cfg := agent.Config{
		AuthTokens:        []string{"endpoint-token"},
		AllowedRoots:      []string{root},
		EnabledOperations: []string{"filesystem.tail"},
		MaxRequestBytes:   65536,
		MaxTailBytes:      10,
	}
	server := httptest.NewServer(agent.NewHandler(agent.NewService(cfg, auditor), cfg))
	defer server.Close()

	connector := newTestSROIAAA(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source:    broker.SourceSROIAAA,
		Action:    "operations.execute",
		Host:      "sgtstubby.arc.gwu.edu",
		Operation: "filesystem.tail",
		Target:    &broker.OperationTarget{Path: logPath},
		Params:    &broker.OperationParams{MaxBytes: 1024},
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if evidence.Source != string(broker.SourceSROIAAA) || evidence.Action != "operations.execute" {
		t.Errorf("provenance = %s %s", evidence.Source, evidence.Action)
	}
	if !evidence.Truncated {
		t.Error("agent truncation status must reach evidence")
	}
	data, ok := evidence.Data.(map[string]any)
	if !ok || data["path"] != resolvedLogPath {
		t.Errorf("Data = %#v", evidence.Data)
	}
	if len(auditor.events) != 1 || auditor.events[0].TargetPath != logPath {
		t.Errorf("agent audit = %#v, want one event for %s", auditor.events, logPath)
	}
}

type recordingAgentAuditor struct {
	events []agent.AuditEvent
}

func (a *recordingAgentAuditor) Record(event agent.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

func TestSROIAAAConnectorRefusesAnUnconfiguredHost(t *testing.T) {
	connector := newTestSROIAAA(t, "http://127.0.0.1:8080")
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source:    broker.SourceSROIAAA,
		Action:    "operations.execute",
		Host:      "other.example.edu",
		Operation: "filesystem.read",
		Target:    &broker.OperationTarget{Path: "/workspace/sample.txt"},
	})
	if err == nil || !strings.Contains(err.Error(), "host_not_configured") {
		t.Fatalf("error = %v, want host_not_configured", err)
	}
}

func TestSROIAAAConnectorDoesNotFollowRedirects(t *testing.T) {
	redirected := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected = true
		if r.Header.Get("Authorization") != "" {
			t.Error("bearer token reached redirect target")
		}
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	connector := newTestSROIAAA(t, redirector.URL)
	_, err := connector.Execute(context.Background(), validSROIAAAStep())
	if err == nil || !strings.Contains(err.Error(), "agent_error") {
		t.Fatalf("error = %v, want redirect refusal", err)
	}
	if redirected {
		t.Error("connector followed an agent-controlled redirect")
	}
}

func TestSROIAAAConnectorRejectsUnsafeEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"http://agent.example.edu:8080",
		"https://agent.example.edu/v1/operations",
		"https://agent.example.edu/?override=true",
	} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := NewSROIAAAConnector(SROIAAAConfig{Agents: map[string]SROIAAAAgentConfig{
				"sgtstubby.arc.gwu.edu": {Endpoint: endpoint, Token: "token"},
			}})
			if err == nil {
				t.Fatal("unsafe endpoint was accepted")
			}
		})
	}
}

func TestParseSROIAAAAgentsRejectsUnknownFields(t *testing.T) {
	_, err := ParseSROIAAAAgents(`{"sgtstubby.arc.gwu.edu":{"endpoint":"https://agent.example.edu","token":"t","extra":true}}`)
	if err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}

func newTestSROIAAA(t *testing.T, endpoint string) *SROIAAAConnector {
	t.Helper()
	connector, err := NewSROIAAAConnector(SROIAAAConfig{Agents: map[string]SROIAAAAgentConfig{
		"sgtstubby.arc.gwu.edu": {Endpoint: endpoint, Token: "endpoint-token"},
	}})
	if err != nil {
		t.Fatalf("NewSROIAAAConnector() error = %v", err)
	}
	return connector
}

func validSROIAAAStep() broker.RouteStep {
	return broker.RouteStep{
		Source:    broker.SourceSROIAAA,
		Action:    "operations.execute",
		Host:      "sgtstubby.arc.gwu.edu",
		Operation: "filesystem.read",
		Target:    &broker.OperationTarget{Path: "/workspace/sample.txt"},
		Params:    &broker.OperationParams{MaxBytes: 128},
	}
}
