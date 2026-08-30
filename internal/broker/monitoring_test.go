package broker

import (
	"strings"
	"testing"
)

// The selectors exist because a page was being read as a population. These
// assert that each one reaches the plan, that the ones a source cannot honour
// are refused rather than dropped, and that a plan carrying them still
// verifies -- Verify reconstructs a plan from its own fields, so a field added
// to a step and not to the reconstruction rejects every plan that uses it.

func testRouter(t *testing.T) *Router {
	t.Helper()
	router, err := NewRouter(Policy{
		Version:   1,
		LiveHosts: map[string]HostPolicy{},
		Resources: map[string]Resource{},
	})
	if err != nil {
		t.Fatalf("NewRouter: %v", err)
	}
	return router
}

func TestMonitoringSelectorsReachThePlan(t *testing.T) {
	router := testRouter(t)

	plan, err := router.Plan(RouteRequest{
		Intent:   IntentMonitoringHistory,
		Since:    "2026-08-29",
		Until:    "2026-08-29",
		Match:    "Zabbix agent is not available",
		Severity: "average",
		State:    "problem",
		Limit:    100,
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	step := plan.Steps[0]
	if step.Match != "Zabbix agent is not available" {
		t.Errorf("match = %q, want it carried to the step", step.Match)
	}
	if step.Severity != "average" || step.State != "problem" || step.Limit != 100 {
		t.Errorf("severity/state/limit = %q/%q/%d", step.Severity, step.State, step.Limit)
	}
	if err := router.Verify(plan); err != nil {
		t.Errorf("Verify rejected a plan the router produced: %v", err)
	}
}

func TestMonitoringLimitDefaultsAndRefusesOversize(t *testing.T) {
	router := testRouter(t)

	plan, err := router.Plan(RouteRequest{Intent: IntentMonitoringProblems})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Steps[0].Limit != DefaultMonitoringLimit {
		t.Errorf("default limit = %d, want %d", plan.Steps[0].Limit, DefaultMonitoringLimit)
	}

	// Clamping instead would hand 200 rows to a caller who asked for 2,000 with
	// nothing in the result to distinguish that from the whole population --
	// and the caller most likely to ask for 2,000 is one who has just been told
	// how many matched.
	_, err = router.Plan(RouteRequest{Intent: IntentMonitoringProblems, Limit: 2000})
	if err == nil {
		t.Fatal("a limit above the cap was accepted")
	}
	if !strings.Contains(err.Error(), "200") {
		t.Errorf("error does not name the cap, so the next attempt is another guess: %v", err)
	}
}

func TestMonitoringProblemsRefusesState(t *testing.T) {
	// Every trigger monitoring.problems can return is firing. Accepting
	// state: "resolved" and ignoring it would answer "what has recovered" with
	// a page of active problems.
	router := testRouter(t)
	_, err := router.Plan(RouteRequest{Intent: IntentMonitoringProblems, State: "resolved"})
	if err == nil {
		t.Fatal("monitoring.problems accepted a state filter it cannot honour")
	}
	if !strings.Contains(err.Error(), "monitoring.history") {
		t.Errorf("error does not point at the intent that can answer this: %v", err)
	}
}

func TestNonMonitoringIntentsRefuseSelectors(t *testing.T) {
	// A filter silently dropped returns a wide result that reads as a narrow
	// one, which is the failure mode this codebase keeps finding.
	router := testRouter(t)
	for _, request := range []RouteRequest{
		{Intent: IntentFleetInventory, Match: "wazuh"},
		{Intent: IntentFleetInventory, Severity: "high"},
		{Intent: IntentFleetInventory, Limit: 10},
		{Intent: IntentAgentStatus, Host: "node01", Match: "disk"},
		{Intent: IntentDatabaseQuery, Query: "SELECT 1", Limit: 10},
	} {
		if _, err := router.Plan(request); err == nil {
			t.Errorf("%s accepted a selector it does not apply", request.Intent)
		}
	}
}

func TestMonitoringSelectorsRejectMalformedValues(t *testing.T) {
	router := testRouter(t)
	cases := []struct {
		name    string
		request RouteRequest
	}{
		{"unknown severity", RouteRequest{Intent: IntentMonitoringProblems, Severity: "catastrophic"}},
		{"unknown state", RouteRequest{Intent: IntentMonitoringHistory, Since: "24h", State: "acknowledged"}},
		{"empty match", RouteRequest{Intent: IntentMonitoringProblems, Match: " "}},
		{"negative limit", RouteRequest{Intent: IntentMonitoringProblems, Limit: -1}},
	}
	for _, tc := range cases {
		if _, err := router.Plan(tc.request); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

func TestSeverityNamesResolveToZabbixPriorities(t *testing.T) {
	// The names are the vocabulary evidence already speaks in, so a model that
	// has read one page knows how to narrow the next. A name here that does not
	// resolve would be offered in the tool schema and refused on use.
	for _, name := range SeverityNames() {
		if _, ok := SeverityFloor(name); !ok {
			t.Errorf("severity %q is offered but does not resolve", name)
		}
	}
	floor, _ := SeverityFloor("HIGH")
	if floor != 4 {
		t.Errorf("SeverityFloor(HIGH) = %d, want 4; casing should not decide whether a filter applies", floor)
	}
}

func TestVerifyRejectsAnInflatedLimit(t *testing.T) {
	// A plan is an ordinary JSON document. Raising the limit after planning must
	// fail, because the router would not produce that plan.
	router := testRouter(t)
	plan, err := router.Plan(RouteRequest{Intent: IntentMonitoringProblems, Limit: 50})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	plan.Steps[0].Limit = MaxMonitoringLimit + 1
	if err := router.Verify(plan); err == nil {
		t.Fatal("Verify accepted a plan with a limit above the cap")
	}
}
