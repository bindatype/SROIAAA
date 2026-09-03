package orchestrator

import (
	"strings"
	"testing"

	"github.com/maclach/sroiaaa/internal/broker"
)

// The prompt is English the compiler cannot check, but parts of it are load
// bearing: it names the tool, it enumerates the intents, and several of its
// claims exist because getting them wrong produced a confidently wrong answer.
// These assert the couplings that would otherwise drift silently.

func TestPromptNamesTheTool(t *testing.T) {
	if !strings.Contains(systemPrompt, toolName) {
		t.Errorf("prompt does not mention %q; a renamed tool would leave the model calling one that does not exist", toolName)
	}
}

func TestPromptDescribesEveryIntent(t *testing.T) {
	for _, intent := range broker.AllIntents() {
		if !strings.Contains(systemPrompt, string(intent)) {
			t.Errorf("prompt does not describe intent %q; a model offered an intent it was never told about has to guess its arguments", intent)
		}
	}
}

// The prompt announces how many channels exist before listing them, and the
// two drifted: it said five while listing six, in a document whose entire job
// is to be precise about what the model may ask for.
func TestPromptCountsItsOwnChannels(t *testing.T) {
	spelled := map[int]string{
		4: "four", 5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten",
	}
	want, ok := spelled[len(broker.AllIntents())]
	if !ok {
		t.Fatalf("no spelling for %d intents; extend this table", len(broker.AllIntents()))
	}
	phrase := "these " + want + " evidence channels"
	if !strings.Contains(systemPrompt, phrase) {
		t.Errorf("prompt does not say %q, but the broker offers %d intents", phrase, len(broker.AllIntents()))
	}
}

func TestPromptDescribesEveryToolParameter(t *testing.T) {
	// A field absent from the prompt is a field the model infers the name of.
	// database.query was usable only by accident until "query" was declared.
	definition := ToolDefinition([]string{"database.query"}).(map[string]any)
	function := definition["function"].(map[string]any)
	parameters := function["parameters"].(map[string]any)
	properties := parameters["properties"].(map[string]any)

	for name := range properties {
		if !strings.Contains(systemPrompt, name) {
			t.Errorf("tool parameter %q is never mentioned in the prompt", name)
		}
	}
}

func TestPromptRetainsItsHardWonRules(t *testing.T) {
	// Each of these is in the prompt because its absence produced a specific
	// wrong answer. Removing one should require deleting a test and saying why.
	// Needles name the substance of a rule, not a sentence. The prompt was
	// rewritten once and every phrase-tied needle fired, which is the test
	// working -- but a needle pinned to wording has to be relaxed on every
	// edit until it stops meaning anything.
	rules := []struct {
		needle string
		why    string
	}{
		{"authoritative job outcome",
			"using DerivedExitCode reported 26 failures against a true 496"},
		{"UNIX_TIMESTAMP",
			"comparing an integer column to a datetime silently matched zero rows"},
		{"total_matching",
			"without comparing it to returned, a truncated result reads as complete"},
		{"proof of absence",
			"an empty Zabbix result was reported as 'no critical CVEs'"},
		{"reassur",
			"the same failure, stated as a reassurance rather than a finding"},
		{"NOT LIKE 'CANCELLED%'",
			"State <> 'CANCELLED' keeps suffixed cancellations and shifts wait times by 5%"},
		{"information_schema",
			"the prompt previously implied its own table list was exhaustive"},
		{"collapse rows",
			"an uncollapsed window function filled the result with duplicates"},
		{"breakdown.events_by_host",
			"asked which systems were degraded, a model read a host list off the 25-row page and implied the rest were fine"},
		{"appears twice in the event log",
			"counting event rows without a state filter double-counts every incident that opened and closed in the window"},
		{"Lead with the broken thing",
			"a literally-true \"no host has lost its agent since 05:00\" led an answer whose body reported 19 hosts down"},
		{"total_ignoring_time_bound",
			"a bound on monitoring.problems returned 0 agent-down triggers while 19 were firing, and 0 was reported as an all-clear"},
		{"is not in the event log for the window",
			"the event log had 0 agent-down rows since 05:00 while 19 hosts had the agent down right then"},
		{"not answered by asking for more rows",
			"a large result is characterized by the aggregates; raising the limit past the budget returns nothing at all"},
	}
	for _, rule := range rules {
		if !strings.Contains(systemPrompt, rule.needle) {
			t.Errorf("prompt lost %q\n     it was there because: %s", rule.needle, rule.why)
		}
	}
}

func TestPromptAndEvidenceLeaveRoomToAnswer(t *testing.T) {
	// Every model on this gateway is capped at 32k tokens regardless of its
	// native context, which is roughly 128 KB. The prompt and a maximal
	// evidence payload both travel on the synthesis turn, so together they must
	// leave room for the question, the tool call and an answer of useful
	// length. Three quarters is the line.
	const window = 32000 * 4
	// The compiled defaults, not the environment override: this asserts that
	// the shipped configuration is safe for the models actually in use.
	used := len(systemPrompt) + maxEvidenceJSON
	if used > window*3/4 {
		t.Errorf("prompt (%d) plus max evidence (%d) is %d of a %d byte window, leaving %d for the answer",
			len(systemPrompt), maxEvidenceJSON, used, window, window-used)
	}
}

func TestEvidenceBudgetExceedsWhatConnectorsReturn(t *testing.T) {
	// A connector allowed to return more than this will produce a query that
	// succeeds against the database and is then rejected here, which reads to
	// the caller as a failure of the query rather than of the configuration.
	const largestConnectorPayload = 48 * 1024 // pegasusMaxTotalBytes
	if maxEvidenceJSON <= largestConnectorPayload {
		t.Errorf("evidence budget %d does not exceed the largest connector payload %d",
			maxEvidenceJSON, largestConnectorPayload)
	}
}

// TestPromptTeachesTicketAgeDirection guards the mapping the model got wrong
// in the field on 2026-09-02: "older than N days" is an `until`, not a
// `since`, and it stands alone. The prompt told the model to ask RT for an
// exact count with the bound applied, and separately that a lone `since` is a
// ray; it never said which field carries ticket age. The model sent no bound,
// got 100 of 428 tickets, and tallied dates and owners off the page.
//
// This asserts the guidance is present, not that a model follows it. Only an
// eval can show the second, and there is no RT eval harness yet.
func TestPromptTeachesTicketAgeDirection(t *testing.T) {
	required := []string{
		"`until` bounds the older side",
		"`until: 60d`",
		"breakdown.tickets_by_owner",
	}
	for _, phrase := range required {
		if !strings.Contains(systemPrompt, phrase) {
			t.Errorf("prompt no longer teaches ticket age direction: missing %q", phrase)
		}
	}
}
