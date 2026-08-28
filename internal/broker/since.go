package broker

import (
	"fmt"
	"strings"
	"time"
)

// maxSinceAge bounds how far back a request may reach. A window of years is
// not a filter, and asking a source for everything since 2019 is the same
// unbounded query the limits exist to prevent.
const maxSinceAge = 400 * 24 * time.Hour

// ParseSince validates a time bound and returns it in UTC.
//
// Accepted forms are RFC 3339, a plain date, and a relative window such as
// "24h" or "7d", because a model asked for "today" reaches for the shortest
// thing that could work and a parser that accepts only one form turns a
// well-formed question into a denial.
func ParseSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if len(value) > 64 {
		return time.Time{}, fmt.Errorf("since is too long")
	}

	// The words a question about a time period reaches for first. A model asked
	// "did anything alert today" wrote since: "today", and rejecting that turns
	// a well-formed question into a denial over vocabulary.
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "today":
		return bound(midnight, now)
	case "yesterday":
		return bound(midnight.AddDate(0, 0, -1), now)
	}

	if moment, err := time.Parse(time.RFC3339, value); err == nil {
		return bound(moment.UTC(), now)
	}
	if day, err := time.Parse("2006-01-02", value); err == nil {
		return bound(day.UTC(), now)
	}
	if days, err := parseDays(value); err == nil {
		return bound(now.Add(-days).UTC(), now)
	}
	if window, err := time.ParseDuration(value); err == nil {
		if window <= 0 {
			return time.Time{}, fmt.Errorf("since must be a past window")
		}
		return bound(now.Add(-window).UTC(), now)
	}
	return time.Time{}, fmt.Errorf("since must be RFC 3339, a date such as 2026-08-28, a window such as 24h or 7d, or today or yesterday")
}

// parseDays handles the "7d" form, which time.ParseDuration does not accept.
func parseDays(value string) (time.Duration, error) {
	if len(value) < 2 || value[len(value)-1] != 'd' {
		return 0, fmt.Errorf("not a day window")
	}
	days, err := time.ParseDuration(value[:len(value)-1] + "h")
	if err != nil {
		return 0, err
	}
	return days * 24, nil
}

func bound(moment, now time.Time) (time.Time, error) {
	if moment.After(now.Add(time.Minute)) {
		return time.Time{}, fmt.Errorf("since is in the future")
	}
	if now.Sub(moment) > maxSinceAge {
		return time.Time{}, fmt.Errorf("since reaches further back than %d days", int(maxSinceAge.Hours()/24))
	}
	return moment, nil
}
