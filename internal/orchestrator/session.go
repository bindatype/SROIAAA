package orchestrator

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
	"github.com/maclach/sroiaaa/internal/connector"
)

//go:embed prompt.md
var systemPrompt string

const (
	toolName = "sroiaaa_evidence"
	// Headroom above what any connector will return, so evidence is rejected
	// here only if a connector's own bound has failed.
	maxEvidenceJSON = 64 * 1024
)

// ToolDefinition is the single tool exposed to the model. Its schema is the
// entire surface a model can influence: an intent, and optionally a host or
// resource alias. Everything else about execution is resolved by policy.
func ToolDefinition(intents []string) any {
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
						"enum":        intents,
						"description": "Which bounded question to ask.",
					},
					"host": map[string]any{
						"type":        "string",
						"description": "Host selector. Required for agent.status and live.evidence.",
					},
					"resource": map[string]any{
						"type":        "string",
						"description": "Policy-defined resource alias. For live.evidence ONLY. Never put SQL here.",
					},
					"query": map[string]any{
						"type":        "string",
						"description": "The SQL for database.query, and the only field SQL may go in. One read-only SELECT, bounded by WHERE.",
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
	intents  []string
	auditor  *Auditor
	model    string
	trace    []TraceEntry
	event    AuditEvent
	started  time.Time
}

// WithAudit attaches an audit destination. Without one the session still works
// but leaves no record, which is the state this replaced.
func (s *Session) WithAudit(auditor *Auditor, model string) *Session {
	s.auditor = auditor
	s.model = model
	return s
}

// TraceEntry records one step of the loop so an operator can see exactly what
// the model proposed and what policy did with it.
type TraceEntry struct {
	Stage   string `json:"stage"`
	Detail  string `json:"detail"`
	Allowed bool   `json:"allowed"`
}

// NewSession wires a model client to a policy router and an executor.
//
// Only intents whose source the executor can actually reach are offered to the
// model. Advertising an intent with no connector behind it presents a
// capability that does not exist, which is the same failure as answering a
// question from a source that cannot see it.
func NewSession(client *MindRouterClient, router *broker.Router, executor *connector.Executor) *Session {
	available := make(map[broker.Source]bool)
	for _, source := range executor.Sources() {
		available[source] = true
	}
	var intents []string
	for _, intent := range broker.AllIntents() {
		if source, ok := broker.SourceForIntent(intent); ok && available[source] {
			intents = append(intents, string(intent))
		}
	}
	return &Session{client: client, router: router, executor: executor, intents: intents}
}

// Intents lists what this session can actually offer a model.
func (s *Session) Intents() []string { return s.intents }

// Trace returns the decisions made during the last Ask.
func (s *Session) Trace() []TraceEntry {
	return s.trace
}

// Ask runs the full loop: propose an intent, validate it against policy,
// execute the resulting plan, and synthesize an answer from the evidence.
func (s *Session) Ask(ctx context.Context, question string) (string, error) {
	s.trace = nil
	s.started = time.Now()
	s.event = AuditEvent{
		RequestID: newRequestID(),
		Question:  question,
		Model:     s.model,
		Decision:  "no_tool_call",
		Status:    "answered",
	}
	defer s.writeAudit()

	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}

	choice, err := s.client.Complete(ctx, messages, []any{ToolDefinition(s.intents)})
	if err != nil {
		return "", err
	}
	if len(choice.Message.ToolCalls) == 0 {
		// Answering without evidence is legitimate: declining a question no
		// source can answer is the behaviour we want, and recording it as a
		// failure would make the audit misleading exactly where refusals matter.
		s.record("model_answered_directly", "no tool call proposed", true)
		answer := strings.TrimSpace(choice.Message.Content)
		s.event.AnswerChars = len(answer)
		if answer == "" {
			s.event.Status = "failed"
			return "", fmt.Errorf("model returned neither a tool call nor an answer")
		}
		return answer, nil
	}

	call := choice.Message.ToolCalls[0]
	if call.Function.Name != toolName {
		s.record("tool_rejected", fmt.Sprintf("model requested unknown tool %q", call.Function.Name), false)
		return "", fmt.Errorf("model requested unknown tool %q", call.Function.Name)
	}
	s.record("intent_proposed", call.Function.Arguments, true)
	s.event.Proposed = call.Function.Arguments

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
		s.event.Decision = "denied"
		// A malformed call and a refused one are different things. Putting SQL
		// in the wrong field is a mistake the model can fix, and returning it
		// to the reader helps nobody. Being told a host is not authorized is an
		// answer, and offering a second attempt would turn a refusal into an
		// invitation to look for a host that is.
		if !isRetryableRouteError(err) {
			return "", fmt.Errorf("policy denied the proposed intent: %w", err)
		}
		retried, retryErr := s.retryWithError(ctx, messages, choice, call, err)
		if retryErr != nil {
			return "", retryErr
		}
		if retried == nil {
			return "", fmt.Errorf("policy denied the proposed intent: %w", err)
		}
		return s.synthesize(ctx, messages, choice, call, *retried)
	}
	planJSON, _ := json.Marshal(plan)
	s.record("policy_allowed", string(planJSON), true)
	s.event.Decision = "allowed"
	s.event.Plan = planJSON

	result, err := s.executor.Execute(ctx, plan)
	if err != nil {
		// A source that executes a statement the model composed can fail for
		// reasons the model can fix -- a reserved word left unquoted, a column
		// that does not exist. Returning the error to the model once is far
		// more useful than returning it to the reader, who did not write the
		// query and cannot correct it. Exactly one retry, so a model that
		// cannot fix its own mistake fails rather than looping.
		retried, retryErr := s.retryWithError(ctx, messages, choice, call, err)
		if retryErr != nil {
			return "", retryErr
		}
		if retried == nil {
			return "", fmt.Errorf("execute plan: %w", err)
		}
		result = *retried
	}

	return s.synthesize(ctx, messages, choice, call, result)
}

// synthesize returns evidence to the model and collects the written answer.
func (s *Session) synthesize(ctx context.Context, messages []Message, choice Choice, call ToolCall, result connector.Result) (string, error) {
	evidenceJSON, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("encode evidence: %w", err)
	}
	if len(evidenceJSON) > maxEvidenceJSON {
		return "", fmt.Errorf("evidence exceeded %d bytes; narrow the request", maxEvidenceJSON)
	}
	s.record("evidence_collected", fmt.Sprintf("%d source(s)", len(result.Evidence)), true)
	for _, evidence := range result.Evidence {
		s.event.Calls = append(s.event.Calls, AuditCall{
			Source:     evidence.Source,
			Action:     evidence.Action,
			Endpoint:   evidence.Endpoint,
			Query:      evidence.Query,
			DurationMS: evidence.DurationMS,
			ItemCount:  evidence.ItemCount,
			Truncated:  evidence.Truncated,
			Summary:    evidence.Summary,
		})
	}

	messages = append(messages,
		Message{Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls},
		Message{Role: "tool", ToolCallID: call.ID, Name: toolName, Content: string(evidenceJSON)},
	)

	final, err := s.client.Complete(ctx, messages, nil)
	if err != nil {
		return "", err
	}
	answer := strings.TrimSpace(final.Message.Content)
	if answer == "" {
		// An empty answer is the worst failure available: the caller cannot tell
		// it apart from success, and evidence was collected to produce nothing.
		s.record("empty_answer", "model returned no content", false)
		return "", fmt.Errorf("model returned an empty answer after collecting evidence")
	}
	s.record("answer_synthesized", "", true)
	s.event.AnswerChars = len(answer)
	return answer, nil
}

func (s *Session) record(stage, detail string, allowed bool) {
	s.trace = append(s.trace, TraceEntry{Stage: stage, Detail: detail, Allowed: allowed})
}

// retryWithError gives the model one chance to correct a failed execution.
// It returns nil, nil when no retry is warranted or the second attempt was no
// better, leaving the caller to report the original failure.
func (s *Session) retryWithError(ctx context.Context, messages []Message, choice Choice, call ToolCall, cause error) (*connector.Result, error) {
	s.record("execution_failed", cause.Error(), false)

	followUp := append(append([]Message(nil), messages...),
		Message{Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls},
		Message{Role: "tool", ToolCallID: call.ID, Name: toolName,
			Content: fmt.Sprintf(`{"error":%q,"guidance":"The request failed. Correct it and call the tool once more. Do not apologize or explain; just issue the corrected call."}`, cause.Error())},
	)

	retry, err := s.client.Complete(ctx, followUp, []any{ToolDefinition(s.intents)})
	if err != nil {
		return nil, err
	}
	if len(retry.Message.ToolCalls) == 0 {
		return nil, nil
	}
	retryCall := retry.Message.ToolCalls[0]
	if retryCall.Function.Name != toolName {
		return nil, nil
	}
	s.record("retry_proposed", retryCall.Function.Arguments, true)

	request, err := broker.DecodeRouteRequest(newLimitedReader(retryCall.Function.Arguments))
	if err != nil {
		s.record("retry_rejected", err.Error(), false)
		return nil, nil
	}
	plan, err := s.router.Plan(request)
	if err != nil {
		s.record("retry_denied", err.Error(), false)
		return nil, nil
	}

	result, err := s.executor.Execute(ctx, plan)
	if err != nil {
		s.record("retry_failed", err.Error(), false)
		return nil, nil
	}
	// A question denied and then corrected is neither a plain denial nor a
	// clean pass. Recording it as "denied" understates what happened, and as
	// "allowed" hides that the first attempt was refused.
	s.record("retry_succeeded", "", true)
	s.event.Decision = "allowed_on_retry"
	retryPlanJSON, _ := json.Marshal(plan)
	s.event.Plan = retryPlanJSON
	return &result, nil
}

// isRetryableRouteError reports whether a denial describes a malformed request
// rather than a refused one. Authorization outcomes are never retried.
func isRetryableRouteError(err error) bool {
	var routeErr *broker.RouteError
	if !errors.As(err, &routeErr) {
		return false
	}
	switch routeErr.Code {
	case "invalid_request", "invalid_query", "invalid_host", "invalid_resource",
		"missing_host", "missing_resource", "unknown_intent":
		return true
	default:
		// host_not_authorized and resource_not_authorized land here.
		return false
	}
}

// writeAudit records the event, filling in the outcome from the trace. It runs
// on every path out of Ask, so a denial or a failure is recorded as faithfully
// as an answer.
func (s *Session) writeAudit() {
	if s.auditor == nil {
		return
	}
	s.event.DurationMS = time.Since(s.started).Milliseconds()
	if s.event.AnswerChars == 0 && s.event.Status == "answered" {
		s.event.Status = "failed"
		for _, entry := range s.trace {
			if !entry.Allowed {
				s.event.Error = entry.Stage + ": " + entry.Detail
			}
		}
	}
	if err := s.auditor.Record(s.event); err != nil {
		// Deliberately visible. An audit that fails quietly is worse than none,
		// because it invites the belief that a record exists.
		fmt.Fprintf(os.Stderr, "sroiaaa: AUDIT WRITE FAILED: %v\n", err)
	}
}

// newRequestID returns a short correlation identifier.
func newRequestID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
