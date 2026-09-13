package main

import (
	"testing"
	"time"
)

func TestParseWindowValid(t *testing.T) {
	cases := []struct {
		in        string
		wantStart int
		wantEnd   int
	}{
		{"09:00-17:00", 540, 1020},
		{"00:00-06:00", 0, 360},
		{"22:00-06:00", 1320, 360},  // overnight
		{"23:59-00:01", 1439, 1},    // overnight, boundary
		{" 8:05 - 9:10 ", 485, 550}, // whitespace tolerated
	}
	for _, c := range cases {
		s, e, err := parseWindow(c.in)
		if err != nil {
			t.Errorf("parseWindow(%q) unexpected error: %v", c.in, err)
			continue
		}
		if s != c.wantStart || e != c.wantEnd {
			t.Errorf("parseWindow(%q) = (%d,%d), want (%d,%d)", c.in, s, e, c.wantStart, c.wantEnd)
		}
	}
}

func TestParseWindowInvalid(t *testing.T) {
	for _, in := range []string{
		"", "abc", "09:00", "09:00-09:00", // empty window
		"25:00-06:00", "09:60-10:00", // out of range
		"09-10:00", "09:00:00-10:00", // bad shape
		"09:00--10:00",
	} {
		if _, _, err := parseWindow(in); err == nil {
			t.Errorf("parseWindow(%q) expected error, got nil", in)
		}
	}
}

func TestInWindow(t *testing.T) {
	cases := []struct {
		start, end, now int
		want            bool
	}{
		{540, 1020, 539, false},
		{540, 1020, 540, true},  // inclusive start
		{540, 1020, 1019, true}, // exclusive end
		{540, 1020, 1020, false},
		{1320, 360, 1319, false}, // overnight
		{1320, 360, 1320, true},
		{1320, 360, 0, true},
		{1320, 360, 359, true},
		{1320, 360, 360, false},
		{1320, 360, 700, false},
	}
	for _, c := range cases {
		if got := inWindow(c.start, c.end, c.now); got != c.want {
			t.Errorf("inWindow(%d,%d,%d) = %v, want %v", c.start, c.end, c.now, got, c.want)
		}
	}
}

func TestWindowsOverlap(t *testing.T) {
	if !windowsOverlap(540, 1020, 600, 700) {
		t.Error("contained windows should overlap")
	}
	if !windowsOverlap(1320, 360, 0, 120) {
		t.Error("overnight vs early-morning should overlap")
	}
	if !windowsOverlap(1320, 360, 1200, 1400) {
		t.Error("overnight vs evening should overlap")
	}
	if windowsOverlap(540, 1020, 1020, 1200) {
		t.Error("adjacent windows should not overlap")
	}
	if windowsOverlap(540, 600, 700, 800) {
		t.Error("disjoint windows should not overlap")
	}
}

func TestParseDays(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"daily", "*"},
		{"", "*"},
		{"*", "*"},
		{"weekdays", "mon,tue,wed,thu,fri"},
		{"weekend", "sat,sun"},
		{"mon", "mon"},
		{"Monday,Wed,FRI", "mon,wed,fri"},
		{"mon,mon,tue", "mon,tue"}, // deduped
	}
	for _, c := range cases {
		got, err := parseDays(c.in)
		if err != nil {
			t.Errorf("parseDays(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseDays(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := parseDays("funday"); err == nil {
		t.Error("parseDays(funday) expected error, got nil")
	}
}

func TestDayMatches(t *testing.T) {
	monday := time.Date(2026, time.September, 14, 12, 0, 0, 0, time.UTC) // a Monday
	if monday.Weekday() != time.Monday {
		t.Fatal("test setup: date is not a Monday")
	}
	if !dayMatches("*", monday) {
		t.Error("'*' should match any day")
	}
	if !dayMatches("mon,wed", monday) {
		t.Error("'mon,wed' should match Monday")
	}
	if dayMatches("tue,wed", monday) {
		t.Error("'tue,wed' should not match Monday")
	}
	if !dayMatches("monday", monday) {
		t.Error("full day names are normalized, should match")
	}
	sunday := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	if !dayMatches("sat,sun", sunday) {
		t.Error("'sat,sun' should match Sunday")
	}
	if dayMatches("mon,tue,wed,thu,fri", sunday) {
		t.Error("weekdays should not match Sunday")
	}
}

func TestDaysIntersect(t *testing.T) {
	if !daysIntersect("*", "mon") || !daysIntersect("mon", "*") {
		t.Error("'*' intersects everything")
	}
	if !daysIntersect("mon,tue", "tue,wed") {
		t.Error("shared day should intersect")
	}
	if daysIntersect("mon", "tue") {
		t.Error("disjoint days should not intersect")
	}
}
