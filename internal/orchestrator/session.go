package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/maclach/sroiaaa/internal/broker"
	"github.com/maclach/sroiaaa/internal/connector"
)

const (
	toolName        = "sroiaaa_evidence"
	maxEvidenceJSON = 96 * 1024

	systemPrompt = `You are an infrastructure diagnostic assistant for the RTS environment.

You cannot access any system directly. To obtain evidence you must call the ` + toolName + ` tool,
which routes through a trusted policy broker. You may only choose an intent and, where the intent
allows, a host or resource alias. You cannot choose URLs, API methods, credentials, or file paths.

Intents, and what each can and cannot answer:

  fleet.inventory      Wazuh agent inventory and connection state. Takes no host.
  agent.status         one Wazuh agent's connection state. Requires an exact agent name.
  monitoring.problems  active Zabbix problem triggers. Host optional and narrows the result.
  live.evidence        a policy-approved file from a SROIAAA endpoint. Requires host and resource.

These four intents are the ONLY evidence available to you. Nothing here reports
vulnerabilities or CVEs, installed packages or patch level, log contents, user
accounts, configuration, performance history, or hardware inventory. If a
question needs something outside these four, say plainly that the data source
is not available. Do NOT route the question to the nearest intent and answer
from whatever comes back.

Absence of evidence is not evidence of absence. An empty or zero result means
no matching records were returned, which is not the same as the condition being
absent. Never turn an empty result into a reassurance. This matters most for
questions about safety or security: if you have no data source for something,
saying "none were found" is a false assurance, and you must not say it.

Host names must be exact. A name covering a range, such as "log001-004", is not
a host. If evidence indicates a host was not found, say so, and do not report
its absence of problems as though the host were healthy.

When you receive evidence, answer from it only. Never invent hosts, counts, or timestamps.

For any count or total, you MUST use the numbers in the "summary" object. Do not tally the
"items" list yourself; "items" may be a bounded sample and hand counting is unreliable. If a
count you need is absent from "summary", say it is not available rather than deriving it.
If the evidence is marked truncated, say so rather than characterizing the whole population.
Be concise and specific, and name the hosts that matter.`
)

// ToolDefinition is the single tool exposed to the model. Its schema is the
// entire surface a model can influence: an intent, and optionally a host or
// resource alias. Everything else about execution is resolved by policy.
func ToolDefinition() any {
	return map[string]any{
		"type": "function",
		"function": map[string]any{
			"name": toolName,
			"description": "Retrieve bounded, read-only infrastructure evidence through the SROIAAA policy broker. " +
				"Covers Wazuh agent inventory and connection state, and active Zabbix problem triggers. " +
				"Does NOT cover vulnerabilities or CVEs, installed packages, patch level, log contents, " +
				"user accounts, configuration, or performance history. Do not call this for questions it cannot answer.",
			"parameters": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"intent": map[string]any{
						"type":        "string",
						"enum":        []string{"fleet.inventory", "agent.status", "monitoring.problems", "live.evidence"},
						"description": "Which bounded question to ask.",
					},
					"host": map[string]any{
						"type":        "string",
						"description": "Host selector. Required for agent.status and live.evidence.",
					},
					"resource": map[string]any{
						"type":        "string",
						"description": "Policy-defined resource alias. Required for live.evidence.",
					},
				},
				"required":             []string{"intent"},
				"additionalProperties": false,
			},
		},
	}
}

// Session runs one question through the model, the broker, and back.
type Session struct {
	client   *MindRouterClient
	router   *broker.Router
	executor *connector.Executor
	trace    []TraceEntry
}

// TraceEntry records one step of the loop so an operator can see exactly what
// the model proposed and what policy did with it.
type TraceEntry struct {
	Stage   string `json:"stage"`
	Detail  string `json:"detail"`
	Allowed bool   `json:"allowed"`
}

// NewSession wires a model client to a policy router and an executor.
func NewSession(client *MindRouterClient, router *broker.Router, executor *connector.Executor) *Session {
	return &Session{client: client, router: router, executor: executor}
}

// Trace returns the decisions made during the last Ask.
func (s *Session) Trace() []TraceEntry {
	return s.trace
}

// Ask runs the full loop: propose an intent, validate it against policy,
// execute the resulting plan, and synthesize an answer from the evidence.
func (s *Session) Ask(ctx context.Context, question string) (string, error) {
	s.trace = nil
	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}

	choice, err := s.client.Complete(ctx, messages, []any{ToolDefinition()})
	if err != nil {
		return "", err
	}
	if len(choice.Message.ToolCalls) == 0 {
		s.record("model_answered_directly", "no tool call proposed", true)
		return choice.Message.Content, nil
	}

	call := choice.Message.ToolCalls[0]
	if call.Function.Name != toolName {
		s.record("tool_rejected", fmt.Sprintf("model requested unknown tool %q", call.Function.Name), false)
		return "", fmt.Errorf("model requested unknown tool %q", call.Function.Name)
	}
	s.record("intent_proposed", call.Function.Arguments, true)

	// The model's arguments are untrusted input. They are decoded with the same
	// strictness the broker applies to any route request, then authorized by
	// policy before anything executes.
	request, err := broker.DecodeRouteRequest(newLimitedReader(call.Function.Arguments))
	if err != nil {
		s.record("intent_rejected", err.Error(), false)
		return "", fmt.Errorf("model proposed an undecodable intent: %w", err)
	}

	plan, err := s.router.Plan(request)
	if err != nil {
		s.record("policy_denied", err.Error(), false)
		return "", fmt.Errorf("policy denied the proposed intent: %w", err)
	}
	planJSON, _ := json.Marshal(plan)
	s.record("policy_allowed", string(planJSON), true)

	result, err := s.executor.Execute(ctx, plan)
	if err != nil {
		return "", fmt.Errorf("execute plan: %w", err)
	}

	evidenceJSON, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode evidence: %w", err)
	}
	if len(evidenceJSON) > maxEvidenceJSON {
		return "", fmt.Errorf("evidence exceeded %d bytes; narrow the request", maxEvidenceJSON)
	}
	s.record("evidence_collected", fmt.Sprintf("%d source(s)", len(result.Evidence)), true)

	messages = append(messages,
		Message{Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls},
		Message{Role: "tool", ToolCallID: call.ID, Name: toolName, Content: string(evidenceJSON)},
	)

	final, err := s.client.Complete(ctx, messages, nil)
	if err != nil {
		return "", err
	}
	s.record("answer_synthesized", "", true)
	return final.Message.Content, nil
}

func (s *Session) record(stage, detail string, allowed bool) {
	s.trace = append(s.trace, TraceEntry{Stage: stage, Detail: detail, Allowed: allowed})
}
