package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maclach/sroiaaa/internal/broker"
)

func TestZabbixConnectorNormalizesTriggers(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json-rpc" {
			t.Errorf("Content-Type = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "countOutput") {
			// The count call intentionally strips presentation parameters, so
			// it must not overwrite what the data call sent.
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"2"}`)
			return
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"triggerid":"101","description":"Disk space low","priority":"4","value":"1","lastchange":"1756300000","hosts":[{"host":"node01"}]},
			{"triggerid":"102","description":"Agent unreachable","priority":"2","value":"1","lastchange":"1756300100","hosts":[{"host":"node02"}]}
		]}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	evidence, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
		Limit:  25,
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	if captured["method"] != "trigger.get" {
		t.Errorf("method = %v, want trigger.get", captured["method"])
	}
	// Without expandDescription, Zabbix returns unresolved macros such as
	// {HOST.NAME}, which a model will repeat verbatim to a reader.
	params, _ := captured["params"].(map[string]any)
	if params["expandDescription"] != true {
		t.Error("expandDescription must be requested so trigger macros resolve")
	}
	if evidence.ItemCount != 2 {
		t.Fatalf("ItemCount = %d, want 2", evidence.ItemCount)
	}
	if evidence.Items[0].Severity != "high" {
		t.Errorf("severity = %q, want high", evidence.Items[0].Severity)
	}
	if evidence.Items[0].State != "problem" {
		t.Errorf("state = %q, want problem", evidence.Items[0].State)
	}
	if evidence.Items[0].Host != "node01" {
		t.Errorf("host = %q, want node01", evidence.Items[0].Host)
	}
	if evidence.Source != string(broker.SourceZabbixAPI) {
		t.Errorf("source = %q", evidence.Source)
	}
	if strings.Contains(evidence.Endpoint, "test-token") {
		t.Error("endpoint provenance must not carry credential material")
	}
}

func TestZabbixConnectorRejectsUnplannedAction(t *testing.T) {
	connector := newTestZabbix(t, "https://zabbix.example.edu/api_jsonrpc.php")
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "host.delete",
	})
	if err == nil {
		t.Fatal("expected an unsupported action to be rejected")
	}
	var connErr *ConnectorError
	if !asConnectorError(err, &connErr) || connErr.Code != "unsupported_action" {
		t.Fatalf("error = %v, want unsupported_action", err)
	}
}

func TestZabbixConnectorSurfacesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params.","data":"Not authorised."}}`)
	}))
	defer server.Close()

	connector := newTestZabbix(t, server.URL)
	_, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
	})
	if err == nil {
		t.Fatal("expected a JSON-RPC error to fail the step")
	}
	if !strings.Contains(err.Error(), "Not authorised") {
		t.Errorf("error = %v, want the API message preserved", err)
	}
}

func TestZabbixConnectorBoundsResponseSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[`)
		for i := 0; i < 5000; i++ {
			io.WriteString(w, `{"triggerid":"1","description":"padding padding padding padding","priority":"1","value":"1","hosts":[{"host":"h"}]},`)
		}
		io.WriteString(w, `{"triggerid":"2","description":"end","priority":"1","value":"1","hosts":[{"host":"h"}]}]}`)
	}))
	defer server.Close()

	connector, err := NewZabbixConnector(ZabbixConfig{
		Endpoint:         server.URL,
		Token:            "test-token",
		MaxResponseBytes: 4096,
	})
	if err != nil {
		t.Fatalf("NewZabbixConnector() error = %v", err)
	}
	if _, err := connector.Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
	}); err == nil {
		t.Fatal("expected an oversized response to be rejected")
	}
}

func TestZabbixConnectorRequiresConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config ZabbixConfig
	}{
		{"missing endpoint", ZabbixConfig{Token: "t"}},
		{"missing token", ZabbixConfig{Endpoint: "https://zabbix.example.edu/api_jsonrpc.php"}},
		{"unsupported scheme", ZabbixConfig{Endpoint: "ftp://zabbix.example.edu", Token: "t"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewZabbixConnector(test.config); err == nil {
				t.Fatal("expected configuration to be rejected")
			}
		})
	}
}

func newTestZabbix(t *testing.T, endpoint string) *ZabbixConnector {
	t.Helper()
	connector, err := NewZabbixConnector(ZabbixConfig{Endpoint: endpoint, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewZabbixConnector() error = %v", err)
	}
	return connector
}

func asConnectorError(err error, target **ConnectorError) bool {
	for err != nil {
		if typed, ok := err.(*ConnectorError); ok {
			*target = typed
			return true
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func TestZabbixSummaryCountsBySeverityAndRendersTimestamps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "countOutput") {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"97"}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[
			{"triggerid":"1","description":"a","priority":"5","value":"1","lastchange":"1786576250","hosts":[{"host":"h1"}]},
			{"triggerid":"2","description":"b","priority":"4","value":"1","hosts":[{"host":"h2"}]},
			{"triggerid":"3","description":"c","priority":"4","value":"1","hosts":[{"host":"h3"}]}
		]}`)
	}))
	defer server.Close()

	evidence, err := newTestZabbix(t, server.URL).Execute(context.Background(), broker.RouteStep{
		Source: broker.SourceZabbixAPI,
		Action: "trigger.get",
	})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if evidence.Summary["returned"] != 3 {
		t.Errorf("returned = %d, want 3", evidence.Summary["returned"])
	}
	if evidence.Summary["total_matching"] != 97 {
		t.Errorf("total_matching = %d, want 97", evidence.Summary["total_matching"])
	}
	if !evidence.Truncated {
		t.Error("a bounded page of a larger match set must be marked truncated")
	}
	if evidence.Summary["high"] != 2 {
		t.Errorf("high = %d, want 2", evidence.Summary["high"])
	}
	if evidence.Summary["disaster"] != 1 {
		t.Errorf("disaster = %d, want 1", evidence.Summary["disaster"])
	}
	if got := evidence.Items[0].Fields["last_change"]; !strings.HasPrefix(got, "2026-") {
		t.Errorf("last_change = %q, want an RFC 3339 timestamp", got)
	}
}

func TestZabbixDistinguishesUnknownHostFromHealthyHost(t *testing.T) {
	// Zero problems for a host Zabbix has never heard of must not be reported
	// the same way as zero problems for a monitored host.
	for _, test := range []struct {
		name      string
		hostFound bool
		want      int
	}{
		{"host is monitored and clean", true, 1},
		{"host is not monitored at all", false, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				body := string(raw)
				switch {
				case strings.Contains(body, "host.get"):
					if test.hostFound {
						io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[{"hostid":"1"}]}`)
					} else {
						io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
					}
				case strings.Contains(body, "countOutput"):
					io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0"}`)
				default:
					io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":[]}`)
				}
			}))
			defer server.Close()

			evidence, err := newTestZabbix(t, server.URL).Execute(context.Background(), broker.RouteStep{
				Source: broker.SourceZabbixAPI,
				Action: "trigger.get",
				Host:   "log001-004",
			})
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if got, ok := evidence.Summary["host_known"]; !ok || got != test.want {
				t.Errorf("host_known = %v (present=%v), want %d", got, ok, test.want)
			}
		})
	}
}
