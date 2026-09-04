package broker

import (
	"testing"
	"time"
)

// TestDayBoundsUseTheCallersZone pins the bug that made "today" a 28-hour
// window. ParseSince took the calendar date from a local clock and stamped it
// midnight UTC, which is not a day in either zone: at 20:07 EDT on 3 September
// "today" began at 8pm on the 2nd. An operator asking what happened today also
// got four hours of the previous evening, and nothing in the answer said so.
//
// The failure needs a non-UTC zone to appear at all, which is why every
// existing test missed it -- they pass a UTC clock, where the two
// constructions agree.
func TestDayBoundsUseTheCallersZone(t *testing.T) {
	edt, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata on this host")
	}
	// The exact moment of the failing run: evening in New York, already
	// tomorrow in UTC.
	now := time.Date(2026, 9, 3, 20, 7, 0, 0, edt)

	tests := []struct {
		value string
		parse func(string, time.Time) (time.Time, error)
		want  time.Time
	}{
		{"today", ParseSince, time.Date(2026, 9, 3, 0, 0, 0, 0, edt)},
		{"yesterday", ParseSince, time.Date(2026, 9, 2, 0, 0, 0, 0, edt)},
		{"2026-09-01", ParseSince, time.Date(2026, 9, 1, 0, 0, 0, 0, edt)},
		// until closes the day it names, so "today" ends at tomorrow's start.
		{"today", ParseUntil, time.Date(2026, 9, 4, 0, 0, 0, 0, edt)},
		{"yesterday", ParseUntil, time.Date(2026, 9, 3, 0, 0, 0, 0, edt)},
		{"2026-09-01", ParseUntil, time.Date(2026, 9, 2, 0, 0, 0, 0, edt)},
	}
	for _, test := range tests {
		got, err := test.parse(test.value, now)
		if err != nil {
			t.Errorf("%q: %v", test.value, err)
			continue
		}
		if !got.Equal(test.want) {
			t.Errorf("%q = %s (%s local), want %s (%s local)",
				test.value,
				got.UTC().Format(time.RFC3339), got.In(edt).Format(time.RFC3339),
				test.want.UTC().Format(time.RFC3339), test.want.In(edt).Format(time.RFC3339))
		}
	}

	// The window an operator means by "today" is 24 hours, not 28.
	since, _ := ParseSince("today", now)
	until, _ := ParseUntil("today", now)
	if d := until.Sub(since); d != 24*time.Hour {
		t.Errorf("today spans %v, want 24h", d)
	}
}
