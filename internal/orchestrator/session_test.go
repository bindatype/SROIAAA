package orchestrator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maclach/sroiaaa/internal/broker"
	"github.com/maclach/sroiaaa/internal/connector"
)

// fakeConnector stands in for a real data source so the loop can be tested
// without network access or credentials.
type fakeConnector struct {
	source broker.Source
	calls  []broker.RouteStep
}

func (f *fakeConnector) Source() broker.Source { return f.source }

func (f *fakeConnector) Execute(ctx context.Context, step broker.RouteStep) (connector.Evidence, error) {
	f.calls = append(f.calls, step)
	return connector.Evidence{
		Source:    string(f.source),
		Action:    step.Action,
		ItemCount: 1,
		Items: []connector.EvidenceItem{
			{ID: "001", Host: "node02", Description: "Wazuh agent", State: "disconnected"},
		},
	}, nil
}

func TestSessionRunsFullLoop(t *testing.T) {
	var turns int
	var secondRequest map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mr2_test" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		turns++
		if turns == 1 {
			io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"","tool_calls":[
				{"id":"call_1","type":"function","function":{"name":"sroiaaa_evidence","arguments":"{\"intent\":\"agent.status\",\"host\":\"node02\"}"}}
			]}}]}`)
			return
		}
		json.Unmarshal(body, &secondRequest)
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"node02 is disconnected."}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	answer, err := session.Ask(context.Background(), "is node02 healthy?")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if answer != "node02 is disconnected." {
		t.Errorf("answer = %q", answer)
	}
	if turns != 2 {
		t.Errorf("model turns = %d, want 2", turns)
	}
	if len(fake.calls) != 1 || fake.calls[0].Action != "agents.status" {
		t.Fatalf("connector calls = %+v, want one agents.status", fake.calls)
	}
	if fake.calls[0].Host != "node02" {
		t.Errorf("host = %q, want node02", fake.calls[0].Host)
	}

	// The evidence must be returned to the model as a tool-role message.
	messages, _ := secondRequest["messages"].([]any)
	last, _ := messages[len(messages)-1].(map[string]any)
	if last["role"] != "tool" {
		t.Errorf("final message role = %v, want tool", last["role"])
	}
	if !strings.Contains(last["content"].(string), "disconnected") {
		t.Error("tool message should carry the evidence")
	}
}

func TestSessionDeniesUnauthorizedIntent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"sroiaaa_evidence","arguments":"{\"intent\":\"live.evidence\",\"host\":\"not-authorized\",\"resource\":\"system-log\"}"}}
		]}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceSROIAAA}
	session := newTestSession(t, server.URL, fake)

	if _, err := session.Ask(context.Background(), "read the log on not-authorized"); err == nil {
		t.Fatal("expected policy to deny an unauthorized host")
	}
	if len(fake.calls) != 0 {
		t.Errorf("connector was called %d times; policy must block before execution", len(fake.calls))
	}

	var denied bool
	for _, entry := range session.Trace() {
		if entry.Stage == "policy_denied" {
			denied = true
		}
	}
	if !denied {
		t.Error("trace should record the policy denial")
	}
}

func TestSessionRejectsInventedToolArguments(t *testing.T) {
	// A model that tries to smuggle an execution detail past policy must be
	// rejected by strict decoding, not silently ignored.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"sroiaaa_evidence","arguments":"{\"intent\":\"fleet.inventory\",\"url\":\"https://evil.example/api\"}"}}
		]}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	if _, err := session.Ask(context.Background(), "list agents"); err == nil {
		t.Fatal("expected an unknown tool-argument field to be rejected")
	}
	if len(fake.calls) != 0 {
		t.Error("nothing should execute after an undecodable intent")
	}
}

func TestSessionPassesThroughDirectAnswers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"I need a host name."}}]}`)
	}))
	defer server.Close()

	fake := &fakeConnector{source: broker.SourceWazuhAPI}
	session := newTestSession(t, server.URL, fake)

	answer, err := session.Ask(context.Background(), "check that host")
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if answer != "I need a host name." {
		t.Errorf("answer = %q", answer)
	}
	if len(fake.calls) != 0 {
		t.Error("no tool call means no execution")
	}
}

func newTestSession(t *testing.T, endpoint string, c connector.Connector) *Session {
	t.Helper()

	client, err := NewMindRouterClient(MindRouterConfig{
		Endpoint: endpoint,
		APIKey:   "mr2_test",
		Model:    "test-model",
	})
	if err != nil {
		t.Fatalf("NewMindRouterClient() error = %v", err)
	}

	policy, err := broker.LoadPolicy(strings.NewReader(`{
		"version": 1,
		"live_hosts": {"docker-harness": {"resources": ["system-log"]}},
		"resources": {"system-log": {"operation": "filesystem.tail", "path": "/var/log/sroiaaa/system.log", "params": {"max_bytes": 8192}}}
	}`))
	if err != nil {
		t.Fatalf("LoadPolicy() error = %v", err)
	}
	router, err := broker.NewRouter(policy)
	if err != nil {
		t.Fatalf("NewRouter() error = %v", err)
	}
	executor, err := connector.NewExecutor(c)
	if err != nil {
		t.Fatalf("NewExecutor() error = %v", err)
	}
	return NewSession(client, router, executor)
}

func TestSessionOffersOnlyExecutableIntents(t *testing.T) {
	// A capability advertised with no connector behind it is a capability that
	// does not exist. The enum must follow what the executor can reach.
	tests := []struct {
		name   string
		source broker.Source
		want   []string
		absent string
	}{
		{
			name:   "zabbix only",
			source: broker.SourceZabbixAPI,
			want:   []string{"monitoring.problems"},
			absent: "fleet.inventory",
		},
		{
			name:   "wazuh only",
			source: broker.SourceWazuhAPI,
			want:   []string{"fleet.inventory", "agent.status"},
			absent: "live.evidence",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session := newTestSession(t, "http://unused.invalid", &fakeConnector{source: test.source})
			got := strings.Join(session.Intents(), ",")
			for _, want := range test.want {
				if !strings.Contains(got, want) {
					t.Errorf("intents = %q, want it to include %q", got, want)
				}
			}
			if strings.Contains(got, test.absent) {
				t.Errorf("intents = %q, must not include %q with no connector for it", got, test.absent)
			}
		})
	}
}

func TestLiveEvidenceIsWithheldUntilItsConnectorExists(t *testing.T) {
	// There is no SROIAAA endpoint connector yet. Until there is, the intent
	// must not reach the model: the router would authorize it and execution
	// would then fail with an internal error.
	session := newTestSession(t, "http://unused.invalid", &fakeConnector{source: broker.SourceZabbixAPI})
	for _, intent := range session.Intents() {
		if intent == string(broker.IntentLiveEvidence) {
			t.Fatal("live.evidence was offered with no sroiaaa-agent connector registered")
		}
	}
}
