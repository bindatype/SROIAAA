package broker

import (
	"errors"
	"strings"
	"testing"
)

func TestRouterPlansCentralDataSources(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name    string
		request RouteRequest
		source  Source
		action  string
	}{
		{
			name:    "fleet inventory uses Wazuh API",
			request: RouteRequest{Intent: IntentFleetInventory},
			source:  SourceWazuhAPI,
			action:  "agents.list",
		},
		{
			name:    "agent status uses Wazuh API",
			request: RouteRequest{Intent: IntentAgentStatus, Host: "node01.example.edu"},
			source:  SourceWazuhAPI,
			action:  "agents.status",
		},
		{
			name:    "monitoring problems use Zabbix API",
			request: RouteRequest{Intent: IntentMonitoringProblems, Host: "node01.example.edu"},
			source:  SourceZabbixAPI,
			action:  "trigger.get",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := router.Plan(test.request)
			if err != nil {
				t.Fatalf("plan route: %v", err)
			}
			if plan.Version != 1 || len(plan.Steps) != 1 {
				t.Fatalf("unexpected plan envelope: %+v", plan)
			}
			if plan.Steps[0].Source != test.source || plan.Steps[0].Action != test.action {
				t.Fatalf("unexpected route step: %+v", plan.Steps[0])
			}
		})
	}
}

func TestRouterResolvesAuthorizedLiveResource(t *testing.T) {
	router := newTestRouter(t)

	plan, err := router.Plan(RouteRequest{
		Intent:   IntentLiveEvidence,
		Host:     "node01.example.edu",
		Resource: "system-messages",
	})
	if err != nil {
		t.Fatalf("plan route: %v", err)
	}

	step := plan.Steps[0]
	if step.Source != SourceSROIAAA || step.Operation != "filesystem.tail" {
		t.Fatalf("unexpected live route: %+v", step)
	}
	if step.Target == nil || step.Target.Path != "/var/log/messages" {
		t.Fatalf("expected policy path, got %+v", step.Target)
	}
	if step.Params == nil || step.Params.MaxBytes != 8192 {
		t.Fatalf("expected policy limits, got %+v", step.Params)
	}
}

func TestRouterDeniesUnauthorizedLiveRoutes(t *testing.T) {
	router := newTestRouter(t)
	tests := []struct {
		name    string
		request RouteRequest
		code    string
	}{
		{
			name:    "unknown host",
			request: RouteRequest{Intent: IntentLiveEvidence, Host: "node02.example.edu", Resource: "system-messages"},
			code:    "host_not_authorized",
		},
		{
			name:    "resource not allowed on host",
			request: RouteRequest{Intent: IntentLiveEvidence, Host: "node01.example.edu", Resource: "workspace-file"},
			code:    "resource_not_authorized",
		},
		{
			name:    "missing resource",
			request: RouteRequest{Intent: IntentLiveEvidence, Host: "node01.example.edu"},
			code:    "missing_resource",
		},
		{
			name:    "unsupported intent",
			request: RouteRequest{Intent: "shell.execute"},
			code:    "unknown_intent",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := router.Plan(test.request)
			var routeError *RouteError
			if !errors.As(err, &routeError) {
				t.Fatalf("expected RouteError, got %v", err)
			}
			if routeError.Code != test.code {
				t.Fatalf("expected %q, got %q", test.code, routeError.Code)
			}
		})
	}
}

func TestLoadPolicyAndRequestRejectUnknownFields(t *testing.T) {
	_, err := LoadPolicy(strings.NewReader(`{"version":1,"live_hosts":{},"resources":{},"extra":true}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown policy field error, got %v", err)
	}

	_, err = DecodeRouteRequest(strings.NewReader(`{"intent":"live.evidence","path":"/etc/shadow"}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected model-selected path rejection, got %v", err)
	}
}

func TestNewRouterRejectsUnsafeResources(t *testing.T) {
	tests := []struct {
		name     string
		resource Resource
	}{
		{
			name:     "arbitrary operation",
			resource: Resource{Operation: "process.list", Path: "/proc"},
		},
		{
			name:     "relative path",
			resource: Resource{Operation: "filesystem.stat", Path: "etc/passwd"},
		},
		{
			name: "excessive read",
			resource: Resource{
				Operation: "filesystem.read",
				Path:      "/etc/hosts",
				Params:    &OperationParams{MaxBytes: 65537},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewRouter(Policy{
				Version:   1,
				LiveHosts: map[string]HostPolicy{},
				Resources: map[string]Resource{"unsafe": test.resource},
			})
			if err == nil {
				t.Fatal("expected unsafe resource to be rejected")
			}
		})
	}
}

func newTestRouter(t *testing.T) *Router {
	t.Helper()
	router, err := NewRouter(Policy{
		Version: 1,
		LiveHosts: map[string]HostPolicy{
			"node01.example.edu": {Resources: []string{"system-messages"}},
		},
		Resources: map[string]Resource{
			"system-messages": {
				Operation: "filesystem.tail",
				Path:      "/var/log/messages",
				Params:    &OperationParams{MaxBytes: 8192},
			},
			"workspace-file": {
				Operation: "filesystem.read",
				Path:      "/workspace/sample.txt",
				Params:    &OperationParams{MaxBytes: 4096},
			},
		},
	})
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return router
}
