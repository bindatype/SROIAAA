package broker

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	maxQueryLen = 8192
	// maxQueryRows bounds any query the planner authorizes. A model-authored
	// query against a table of eighteen million rows would otherwise be a
	// legitimate SELECT that no context window can hold.
	maxQueryRows = 5000
)

// nonReadVerbs are statement verbs that must not appear in a query.
//
// The database credential grants SELECT on one schema and nothing else, so the
// server already refuses every one of these. This list exists so that a mistake
// is caught while planning, where it can be reported as an invalid query,
// rather than surfacing later as a permission error from the database.
var nonReadVerbs = []string{
	"insert ", "update ", "delete ", "drop ", "alter ", "create ",
	"truncate ", "grant ", "revoke ", "replace ", "rename ", "call ",
	"into outfile", "into dumpfile", "lock ", "unlock ", "set ",
}

// ValidateQuery checks that a model-authored query is a single read.
//
// This is deliberately a thin guard rather than a harness. The filesystem
// reasoning that justifies a bounded operation catalog does not apply here:
// a filesystem is unbounded and holds secrets, whereas this credential is
// confined to one schema and cannot write. What remains worth enforcing is
// that the statement is singular, so that what gets audited is what actually
// ran and a second statement cannot hide behind the first.
func ValidateQuery(query string) error {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return fmt.Errorf("query is empty")
	}
	if len(trimmed) > maxQueryLen {
		return fmt.Errorf("query exceeds %d bytes", maxQueryLen)
	}
	for _, r := range trimmed {
		if r == '\x00' || (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') {
			return fmt.Errorf("query contains control characters")
		}
	}

	lowered := strings.ToLower(trimmed)
	if !strings.HasPrefix(lowered, "select") && !strings.HasPrefix(lowered, "with") {
		return fmt.Errorf("query must begin with SELECT or WITH")
	}

	// This server accepts stacked statements, so a trailing second statement
	// would run unseen by whatever recorded the first.
	if strings.Contains(strings.TrimRight(trimmed, "; \t\n\r"), ";") {
		return fmt.Errorf("only a single statement is allowed")
	}

	for _, verb := range nonReadVerbs {
		if strings.Contains(lowered, verb) {
			return fmt.Errorf("query contains a non-read verb: %q", strings.TrimSpace(verb))
		}
	}
	return nil
}
