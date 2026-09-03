package orchestrator

import (
	"os"
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
	// The count is stated twice, at the top as channels and in the closing
	// contract as intents. Only the first was guarded, and on 2026-09-03 the
	// prompt said eight channels in one place and five intents in the other --
	// two instructions to the same model in the same document, disagreeing.
	// Every place the number appears has to be checked, or guarding one of
	// them just moves the staleness somewhere unwatched.
	for _, phrase := range []string{
		"these " + want + " evidence channels",
		"these " + want + " intents",
	} {
		if !strings.Contains(systemPrompt, phrase) {
			t.Errorf("prompt does not say %q, but the broker offers %d intents",
				phrase, len(broker.AllIntents()))
		}
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

// TestPromptTeachesEndpointEvidence guards the rule that arrived with the
// endpoint connector. live.evidence is the only channel whose result lands in
// `data` rather than `items`, which puts a countable array directly in front
// of a model that is told everywhere else never to count arrays. Without this
// paragraph the model has a raw list, a prohibition, and no stated way to
// answer "how many" that is neither a refusal nor a violation.
func TestPromptTeachesEndpointEvidence(t *testing.T) {
	for _, phrase := range []string{
		"Counts still come from `summary`, never from `data`",
		"`summary.entries`",
		"supports no population claim",
	} {
		if !strings.Contains(systemPrompt, phrase) {
			t.Errorf("prompt no longer tells the model how to read endpoint evidence: missing %q", phrase)
		}
	}
}

// pricedRules are the rules with an incident behind them. Each names the
// marker that delimits it and a phrase that must survive any rewrite.
//
// The prompt has ~128 rules and, before this, three guards. A defensive
// rewrite in August cut it from 12,376 to 10,706 bytes, scored the same on
// the head-to-head suite, and silently dropped three rules -- the runTBL2
// column list cost about two hours of guessed column names before anyone
// worked out why. The lesson recorded then was that a fixed suite only
// measures the shapes it contains. These are the shapes it did not contain.
var pricedRules = []struct {
	marker string
	phrase string
	cost   string
}{
	{"grouped-truncation", "leaves no visible trace",
		"a grouped result loses half its groups with every returned row still well formed"},
	{"runtbl2-columns", "groupName",
		"the model guessed a Hostname column; one wasted turn per host question for ~2 hours"},
	{"unrun-check-not-allclear", "reads as an",
		"\"no critical agents are disconnected\" was posted while five were down"},
	{"lead-with-broken", "people skim",
		"a reader who stops after one sentence gets the opposite impression"},
	{"counts-from-summary", "Never count the `items` list by hand",
		"275 records tallied as 55 against a true 52; a total reported as the page limit"},
	{"no-cve-source", "vulnerabilities or CVEs",
		"a CVE question answered from Zabbix triggers, reporting no critical CVEs for a host that did not exist"},
	{"oldruntbl-compressed", "compressed form",
		"LIKE '%cpu004%' silently misses jobs recorded as cpu[004-005]"},
	{"ingestion-lag", "ingestion frontier",
		"CURDATE() selects a partial day and reports a fraction of it as a total"},
	{"time-bound-contract", "refuse a bound rather than ignore it",
		"live.evidence accepted a bound and dropped it until c9f4c3f"},
	{"rt-metadata-only", "never the ticket body",
		"RT tickets routinely carry user PII and credentials pasted into a support request"},
	{"ticket-age-direction", "bounds the older side",
		"an unbounded fetch tallied 100 of 428 rows by hand, 2026-09-02"},
}

// TestPricedRulesSurvive fails if a rule with a known cost has been reworded
// away. String presence is a weak assertion and that is the point: it is cheap
// enough to keep one per rule, and a rewrite cannot drop the rule without
// turning this red.
func TestPricedRulesSurvive(t *testing.T) {
	for _, rule := range pricedRules {
		if !strings.Contains(systemPrompt, rule.phrase) {
			t.Errorf("the %s rule is gone (%q). What it cost last time: %s",
				rule.marker, rule.phrase, rule.cost)
		}
	}
}

// TestPricedRulesAreMarkedForAblation asserts each is delimited, so its worth
// can be measured by removing it rather than argued about. The markers are
// stripped before the model sees them.
func TestPricedRulesAreMarkedForAblation(t *testing.T) {
	raw := rawPromptForTest(t)
	for _, rule := range pricedRules {
		marker := "<!-- rule:" + rule.marker + " -->"
		if !strings.Contains(raw, marker) {
			t.Errorf("%s carries no ablation marker, so its cost cannot be measured", rule.marker)
			continue
		}
		// A marker not at the start of a line is invisible to the harness
		// regex, which is how one rule was reported removed while its text
		// stayed in place.
		if !strings.Contains(raw, "\n"+marker+"\n") {
			t.Errorf("%s marker is not alone on its own line; the ablation harness will not see it", rule.marker)
		}
	}
}

// TestPromptCarriesNoMarkersIntoTheModel asserts the stripping works. A model
// reading "<!-- rule:grouped-truncation -->" is being handed a name for a rule
// it is supposed to follow, not notice.
func TestPromptCarriesNoMarkersIntoTheModel(t *testing.T) {
	if strings.Contains(systemPrompt, "<!-- rule:") || strings.Contains(systemPrompt, "<!-- /rule -->") {
		t.Error("ablation markers reached the assembled prompt; they must be stripped before the model sees them")
	}
}

// rawPromptForTest reads prompt.md from disk, markers intact. systemPrompt has
// been stripped, so a marker assertion has to read the source.
func rawPromptForTest(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("prompt.md")
	if err != nil {
		t.Fatalf("read prompt.md: %v", err)
	}
	return string(raw)
}
