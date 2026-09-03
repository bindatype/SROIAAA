package orchestrator

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// The prompt is 128 rules and, until now, eleven of them were guarded. The
// other 117 could be reworded, merged or deleted and every test stayed green.
// That is not a hypothetical: a defensive rewrite in August cut the prompt by
// 1,670 bytes, scored identically on the head-to-head suite, and dropped three
// rules. One cost about two hours of guessed column names.
//
// Eleven hand-written guards was the right start -- each carries what its rule
// cost, which a file cannot -- but 117 more would be unmaintainable and nobody
// would keep them current. So the remaining rules are guarded collectively by
// an inventory: every line of prompt content, checked in.
//
// The point is not that the file makes changing the prompt hard. It is that
// removing a rule becomes an explicit line deleted from a reviewed file rather
// than a paragraph quietly not surviving a rewrite.
//
// To record a deliberate change:
//
//	UPDATE_PROMPT_RULES=1 go test ./internal/orchestrator/ -run TestEveryPromptRule
//
// then read the diff. If it deletes lines you did not mean to delete, that is
// the August failure caught before it ships.

const promptRulesFile = "prompt_rules.golden"

// promptContent returns every load-bearing line of the prompt: not headings,
// not ablation markers, not blank lines. Headings are excluded because they
// carry no instruction and are the one thing a restructure is allowed to move
// freely; a restructure that only moves headings should not have to rewrite
// this inventory.
func promptContent(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("prompt.md")
	if err != nil {
		t.Fatalf("read prompt.md: %v", err)
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), " \t")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
		case strings.HasPrefix(trimmed, "#"):
		case strings.HasPrefix(trimmed, "<!-- rule:"), trimmed == "<!-- /rule -->":
		default:
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan prompt.md: %v", err)
	}
	return lines
}

func readGolden(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(promptRulesFile)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with UPDATE_PROMPT_RULES=1)", promptRulesFile, err)
	}
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimRight(line, " \t"))
		}
	}
	return lines
}

// TestEveryPromptRuleSurvives is the guard for the rules that have no
// individual test. A line that disappears from the prompt without disappearing
// from the inventory is a rule lost by accident.
func TestEveryPromptRuleSurvives(t *testing.T) {
	content := promptContent(t)

	if os.Getenv("UPDATE_PROMPT_RULES") != "" {
		if err := os.WriteFile(promptRulesFile, []byte(strings.Join(content, "\n")+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", promptRulesFile, err)
		}
		t.Logf("recorded %d rules to %s -- read the diff before committing", len(content), promptRulesFile)
		return
	}

	present := make(map[string]int, len(content))
	for _, line := range content {
		present[line]++
	}

	var lost []string
	for _, want := range readGolden(t) {
		if present[want] > 0 {
			present[want]--
			continue
		}
		lost = append(lost, want)
	}

	if len(lost) > 0 {
		t.Errorf("%d prompt rule(s) are in %s and no longer in the prompt.\n"+
			"If that was deliberate, delete them from the inventory in the same commit and say why.\n"+
			"If it was not, this is the failure that cost two hours in August.",
			len(lost), promptRulesFile)
		for i, line := range lost {
			if i == 12 {
				t.Errorf("  ... and %d more", len(lost)-12)
				break
			}
			t.Errorf("  LOST: %s", truncateRule(line))
		}
	}

	// Additions are reported too, so the inventory cannot drift into being a
	// record of what the prompt used to say.
	var added []string
	for line, count := range present {
		for i := 0; i < count; i++ {
			added = append(added, line)
		}
	}
	if len(added) > 0 {
		sort.Strings(added)
		t.Errorf("%d prompt line(s) are not recorded in %s. Regenerate with "+
			"UPDATE_PROMPT_RULES=1 so the inventory stays current.", len(added), promptRulesFile)
		for i, line := range added {
			if i == 8 {
				t.Errorf("  ... and %d more", len(added)-8)
				break
			}
			t.Errorf("  NEW: %s", truncateRule(line))
		}
	}
}

// TestPromptInventoryCoversEveryRule asserts the inventory is not empty or
// stale in bulk -- a zero-length or drastically short file would make the guard
// above pass while checking almost nothing, which is the shape of failure this
// project keeps finding.
func TestPromptInventoryCoversEveryRule(t *testing.T) {
	golden, content := readGolden(t), promptContent(t)
	if len(golden) < 200 {
		t.Errorf("the inventory holds %d lines; the prompt has ~239 rules, so this is not guarding "+
			"what it claims to", len(golden))
	}
	if len(golden) != len(content) {
		t.Errorf("inventory has %d lines, prompt has %d; they have drifted apart", len(golden), len(content))
	}
}

func truncateRule(line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 96 {
		return fmt.Sprintf("%s...", line[:96])
	}
	return line
}
