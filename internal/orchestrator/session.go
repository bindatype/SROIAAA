package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
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
  database.query       a read-only SQL query against the pegasusdb HPC accounting
                       database. Requires query. Use this for jobs, scheduler
                       outcomes, and storage usage.

These intents are the ONLY evidence available to you. Nothing here reports
vulnerabilities or CVEs, installed packages or patch level, log contents,
configuration, or hardware inventory.

For database.query, write one SELECT statement against MariaDB.

Live tables:
  runTBL2      job records, current to within hours. SubmitTime, StartTime and
               EndTime are unix integers. Other columns include netid,
               groupName, JobID, NodeList, NNodes, ReqCPUS, State,
               DerivedExitCode and Partition.
  folderstats  daily per-folder storage snapshots: todaysdate, folderpath,
               clustername, capacity_usage, data_usage, num_files.

Column semantics that are easy to get wrong:

- State is the authoritative job outcome. Use it for anything about success
  or failure. Its values include COMPLETED, FAILED, TIMEOUT, NODE_FAIL and
  CANCELLED, and cancellations often carry a suffix, so match those with
  State LIKE 'CANCELLED%'.
- DerivedExitCode is NOT a number. It is a Slurm 'exit:signal' string such as
  '0:0', '0:15' or '1:0'. Comparing it to 0 silently coerces the string and
  produces wrong counts: '0:15' compares equal to 0 even though that job did
  not succeed. Do not use it to determine whether a job failed. Use State.
- Partition is a reserved word in MariaDB. Quote it with backticks.

Units and conventions:

- SubmitTime, StartTime and EndTime are unix integers. Bucket them with
  DATE(FROM_UNIXTIME(SubmitTime)) for days, or
  DATE_FORMAT(FROM_UNIXTIME(SubmitTime), '%Y-%m-%d %H') for hours.
- WaitTime, RunTime and Timelimit exist ONLY in the FY tables, not in
  runTBL2. Any question about wait time, run time or requested time must use
  a fiscal year table.
- WaitTime and RunTime are in SECONDS. Divide by 3600 for hours.
- Timelimit is in MINUTES, so multiply by 60 to compare against RunTime.
- ` + "`" + `partition` + "`" + ` is a reserved word. Write it lowercase and backtick-quoted.
- When analysing wait times, exclude jobs that never started and jobs the
  user abandoned: AND StartTime > 0 AND State <> 'CANCELLED'. Without that,
  never-started jobs distort every average.
- This server is MariaDB 10.3, where percentiles are WINDOW functions and
  require OVER. Write MEDIAN(WaitTime) OVER (PARTITION BY netid) with a
  SELECT DISTINCT, not a plain aggregate with GROUP BY. A median is usually a
  better summary of wait time than AVG.

Choosing a table. Use runTBL2 for recent counts and outcomes; it is current
to within hours but carries no timing columns. Use a fiscal year table for
anything about wait or run time, and for historical analysis inside its
range: FY2026 covers 2025-07-01 to 2026-07-13, earlier years likewise.
nodemetrics stopped in 2022 and should not be used. Querying a table outside
its range returns nothing, which is not the same as nothing having happened.

Always bound a query with a WHERE clause on time, and aggregate in SQL rather
than listing rows when the question is about counts.

Results are capped at a small number of rows. If the evidence summary contains
result_was_capped, you were given an arbitrary slice of a larger result and you
must NOT summarize, total, or characterize it. Say the result was capped, then
issue a second query that does the work in SQL: GROUP BY with COUNT or SUM to
get totals, ORDER BY with LIMIT to get a top-N, MIN, MAX, AVG or MEDIAN for
distributions. Counting rows yourself is exactly how wrong numbers are
produced; the database can count them correctly.

Worked examples, taken from queries this site actually runs:

  -- jobs per day for named users over a window
  SELECT DATE(FROM_UNIXTIME(SubmitTime)) AS day, netid, COUNT(*) AS jobs
  FROM FY2026
  WHERE netid IN ('gunan','hansu')
    AND SubmitTime >= UNIX_TIMESTAMP('2026-05-09')
    AND SubmitTime <  UNIX_TIMESTAMP('2026-06-01')
  GROUP BY day, netid ORDER BY day, netid;

  -- median wait time per user; note DISTINCT and OVER, not GROUP BY
  SELECT DISTINCT netid,
         ROUND(MEDIAN(WaitTime) OVER (PARTITION BY netid)/3600,1) AS p50_wait_hr
  FROM FY2026
  WHERE netid IN ('gunan','hansu')
    AND SubmitTime >= UNIX_TIMESTAMP('2026-05-09')
    AND StartTime > 0 AND State <> 'CANCELLED';

  -- mean wait by user and job width, an ordinary aggregate
  SELECT netid, NCPUS, COUNT(*) AS jobs,
         ROUND(AVG(WaitTime)/3600,1) AS avg_wait_hr
  FROM FY2026
  WHERE NCPUS IN (40,80)
    AND SubmitTime >= UNIX_TIMESTAMP('2026-05-09')
    AND StartTime > 0 AND State <> 'CANCELLED'
  GROUP BY netid, NCPUS;

  -- requested versus actual on one partition
  SELECT ` + "`" + `partition` + "`" + `, WaitTime, Timelimit*60 AS RequestedSeconds, NNodes, NCPUS
  FROM FY2026
  WHERE ` + "`" + `partition` + "`" + ` = 'cpu'
    AND SubmitTime >= UNIX_TIMESTAMP('2026-05-09')
    AND StartTime > 0 AND WaitTime >= 0 AND State <> 'CANCELLED';

When you answer from database.query, state the SQL you ran. The reader cannot
check a number whose derivation is invisible, and a query that runs without
error can still answer a different question than the one asked. If a
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
	intents  []string
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
	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: question},
	}

	choice, err := s.client.Complete(ctx, messages, []any{ToolDefinition(s.intents)})
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
	s.record("retry_succeeded", "", true)
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
