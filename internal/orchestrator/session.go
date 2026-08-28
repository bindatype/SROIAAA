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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/maclach/sroiaaa/internal/broker"
	"github.com/maclach/sroiaaa/internal/connector"
)

//go:embed prompt.md
var embeddedPrompt string

// systemPrompt is the embedded prompt with its rule markers stripped, unless
// SROIAAA_PROMPT names a file to use instead. The override exists so a prompt
// change can be measured without a rebuild; nothing in normal operation reads
// it.
var systemPrompt = loadPrompt()

// ruleMarker labels a block so an experiment can remove it by name. Markers are
// stripped before the prompt is sent, so the model never sees them.
var ruleMarker = regexp.MustCompile(`(?m)^<!-- rule:([a-z0-9-]+) -->\n`)

var ruleEnd = regexp.MustCompile(`(?m)^<!-- /rule -->\n`)

func loadPrompt() string {
	text := embeddedPrompt
	if path := os.Getenv("SROIAAA_PROMPT"); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			text = string(raw)
		}
	}
	text = ruleMarker.ReplaceAllString(text, "")
	return strings.TrimSpace(ruleEnd.ReplaceAllString(text, "")) + "\n"
}

// PromptRules lists the rule blocks the current prompt defines, in order.
func PromptRules() []string {
	var names []string
	for _, match := range ruleMarker.FindAllStringSubmatch(embeddedPrompt, -1) {
		names = append(names, match[1])
	}
	return names
}

const (
	toolName = "sroiaaa_evidence"
	// Headroom above what any connector will return, so evidence is rejected
	// here only if a connector's own bound has failed. SROIAAA_MAX_EVIDENCE
	// raises it in step with a raised connector cap.
	maxEvidenceJSON = 64 * 1024

	// maxToolCalls bounds the work, not the authority: each call is validated
	// and authorized exactly as the first one is. Five is enough to look at a
	// schema, run a query, and correct it once.
	maxToolCalls = 5
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
					"since": map[string]any{
						"type": "string",
						"description": "Bound evidence to what changed after this moment. RFC 3339, a date such as 2026-08-28, " +
							"or a window such as 24h or 7d. Use it for any question about a time period. " +
							"Not for database.query, which bounds time in its WHERE clause.",
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

// Ask answers a question, letting the model work in steps.
//
// It gets several tool calls rather than one. A single call forces every
// question into a single query, which is the wrong shape for the work: asked
// about an unfamiliar table the model reaches for information_schema, and with
// one call that inspection consumes the only turn it had. It would report the
// columns and stop, having never answered. Given room, it can look before it
// queries, count before it aggregates, and correct a query the database
// rejected -- which is how a person would do it.
//
// Every call is validated and authorized independently. More turns is more
// opportunity to work, not more authority.
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
	tools := []any{ToolDefinition(s.intents)}

	forceTool := ""
	for turn := 0; turn < maxToolCalls; turn++ {
		choice, err := s.client.Complete(ctx, messages, tools, forceTool)
		forceTool = ""
		if err != nil {
			return "", err
		}

		if len(choice.Message.ToolCalls) == 0 {
			answer := strings.TrimSpace(choice.Message.Content)

			// A weaker model sometimes writes out the call it means to make --
			// the SQL, the arguments, sometimes a code block -- and stops,
			// having described the action instead of taking it. Returning that
			// hands the caller a plan where an answer should be. With turns
			// left, ask again.
			if describesACallInstead(answer) && turn < maxToolCalls-1 {
				// Asking again in prose is what failed the first time. The next
				// turn names the function in tool_choice, so a call is the only
				// shape the response can take.
				s.record("described_instead_of_called", "model wrote out a tool call rather than making one; forcing the call", false)
				messages = append(messages,
					Message{Role: "assistant", Content: answer},
					Message{Role: "user", Content: "Make that call now."},
				)
				forceTool = toolName
				continue
			}

			if answer == "" {
				s.record("empty_answer", "model returned neither a tool call nor content", false)
				s.event.Status = "failed"
				return "", fmt.Errorf("model returned neither a tool call nor an answer")
			}
			if turn == 0 {
				s.record("model_answered_directly", "no tool call proposed", true)
			} else {
				s.record("answer_synthesized", "", true)
			}
			s.event.AnswerChars = len(answer)
			return answer, nil
		}

		call := choice.Message.ToolCalls[0]
		if call.Function.Name != toolName {
			s.record("tool_rejected", fmt.Sprintf("model requested unknown tool %q", call.Function.Name), false)
			return "", fmt.Errorf("model requested unknown tool %q", call.Function.Name)
		}
		s.record("intent_proposed", call.Function.Arguments, true)
		if s.event.Proposed == "" {
			s.event.Proposed = call.Function.Arguments
		}

		// The model's arguments are untrusted input on every turn, not just the
		// first. They are decoded as strictly as any route request and
		// authorized by policy before anything executes.
		messages = append(messages, Message{
			Role: "assistant", Content: choice.Message.Content, ToolCalls: choice.Message.ToolCalls,
		})

		result, failure := s.runOneCall(ctx, call)
		if failure != nil {
			// A refusal is an answer and ends the loop. A malformed call or a
			// failed query is something the model can correct, so it goes back
			// as a tool result and the loop continues.
			if !failure.recoverable {
				s.event.Decision = "denied"
				return "", failure.err
			}
			messages = append(messages, Message{
				Role: "tool", ToolCallID: call.ID, Name: toolName,
				Content: fmt.Sprintf(`{"error":%q,"guidance":"Correct this and call the tool again."}`, failure.err.Error()),
			})
			continue
		}

		evidenceJSON, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("encode evidence: %w", err)
		}
		if len(evidenceJSON) > evidenceBudget() {
			messages = append(messages, Message{
				Role: "tool", ToolCallID: call.ID, Name: toolName,
				Content: `{"error":"the result was too large to return; narrow it or aggregate in SQL"}`,
			})
			continue
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
		messages = append(messages, Message{
			Role: "tool", ToolCallID: call.ID, Name: toolName, Content: string(evidenceJSON),
		})
	}

	s.record("turn_limit_reached", fmt.Sprintf("%d tool calls without an answer", maxToolCalls), false)
	s.event.Status = "failed"
	return "", fmt.Errorf("gave up after %d tool calls without an answer", maxToolCalls)
}

// callFailure distinguishes a refusal, which ends the loop, from a mistake the
// model can fix, which is returned to it.
type callFailure struct {
	err         error
	recoverable bool
}

// runOneCall validates, authorizes and executes one proposed tool call.
func (s *Session) runOneCall(ctx context.Context, call ToolCall) (connector.Result, *callFailure) {
	request, err := broker.DecodeRouteRequest(newLimitedReader(call.Function.Arguments))
	if err != nil {
		s.record("intent_rejected", err.Error(), false)
		return connector.Result{}, &callFailure{err: fmt.Errorf("undecodable intent: %w", err), recoverable: true}
	}

	plan, err := s.router.Plan(request)
	if err != nil {
		s.record("policy_denied", err.Error(), false)
		// Record the denial even when the model will be allowed another
		// attempt. A request denied and then retried is not the same as one
		// that never proposed anything, and "no_tool_call" says the wrong
		// thing about a model that proposed an intent that does not exist.
		if s.event.Decision == "no_tool_call" {
			s.event.Decision = "denied"
		}
		// Being told a host is not authorized is an answer. Putting a value in
		// the wrong field is a mistake. Only the second earns another attempt.
		return connector.Result{}, &callFailure{
			err:         fmt.Errorf("policy denied the proposed intent: %w", err),
			recoverable: isRetryableRouteError(err),
		}
	}
	planJSON, _ := json.Marshal(plan)
	s.record("policy_allowed", string(planJSON), true)
	s.event.Decision = "allowed"
	s.event.Plan = planJSON

	result, err := s.executor.Execute(ctx, plan)
	if err != nil {
		s.record("execution_failed", err.Error(), false)
		return connector.Result{}, &callFailure{err: err, recoverable: true}
	}
	return result, nil
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

// record appends a decision to the trace, which -trace prints and which
// writeAudit reads to describe the outcome.
func (s *Session) record(stage, detail string, allowed bool) {
	s.trace = append(s.trace, TraceEntry{Stage: stage, Detail: detail, Allowed: allowed})
}

// isRetryableRouteError reports whether a denial describes a malformed request
// rather than a refused one. Authorization outcomes are never retried: putting
// a value in the wrong field is a mistake the model can fix, while being told a
// host is not authorized is an answer, and offering another attempt would turn
// a refusal into an invitation to look for a host that is.
func isRetryableRouteError(err error) bool {
	var routeErr *broker.RouteError
	if !errors.As(err, &routeErr) {
		return false
	}
	switch routeErr.Code {
	case "invalid_request", "invalid_query", "invalid_since", "invalid_host", "invalid_resource",
		"missing_host", "missing_resource", "unknown_intent":
		return true
	default:
		return false
	}
}

// describesACallInstead reports whether an answer looks like a tool call that
// was written out rather than issued. It is a heuristic over model prose, so
// it errs toward letting text through: the cost of a false positive is one
// wasted turn, while a false negative returns a plan to someone who asked a
// question.
func describesACallInstead(answer string) bool {
	if answer == "" {
		return false
	}
	lowered := strings.ToLower(answer)

	// Naming the tool, or naming an intent, while producing no call at all.
	mentionsTheCall := strings.Contains(lowered, strings.ToLower(toolName)) ||
		strings.Contains(lowered, "intent=") ||
		strings.Contains(lowered, `"intent":`) ||
		strings.Contains(lowered, "intent='")

	// Announcing the action rather than reporting a result.
	announces := strings.Contains(lowered, "let's execute") ||
		strings.Contains(lowered, "lets execute") ||
		strings.Contains(lowered, "i will now") ||
		strings.Contains(lowered, "now i will") ||
		strings.Contains(lowered, "let's construct") ||
		strings.Contains(lowered, "i need to query") ||
		strings.Contains(lowered, "execute this via the tool")

	return mentionsTheCall || announces
}

// evidenceBudget is the largest evidence payload this session will hand a
// model. It tracks the connector caps: raising one without the other produces
// a query that succeeds and is then refused.
func evidenceBudget() int {
	if value := os.Getenv("SROIAAA_MAX_EVIDENCE"); value != "" {
		if size, err := strconv.Atoi(value); err == nil && size > 0 {
			return size
		}
	}
	return maxEvidenceJSON
}
