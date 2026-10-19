package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSelectDesiredPicksLatestAndReportsOverlap(t *testing.T) {
	selected, overlaps := selectDesired([]desiredSched{
		{mac: "AA", ip: "192.168.1.5", action: "block", id: 1},
		{mac: "AA", ip: "192.168.1.5", action: "throttle", speed: 64, id: 2},
		{mac: "BB", ip: "192.168.1.6", action: "block", id: 3},
	})
	if len(selected) != 2 {
		t.Fatalf("selected = %+v", selected)
	}
	if got := selected["AA"]; got.id != 2 || got.action != "throttle" || got.speed != 64 {
		t.Fatalf("AA selected = %+v, want latest id 2", got)
	}
	if got := selected["BB"]; got.id != 3 {
		t.Fatalf("BB selected = %+v", got)
	}
	if !reflect.DeepEqual(overlaps["AA"], []int64{1, 2}) {
		t.Fatalf("overlaps[AA] = %v, want [1 2]", overlaps["AA"])
	}
	if len(overlaps["BB"]) != 0 {
		t.Fatalf("BB unexpectedly reported as overlapping: %v", overlaps["BB"])
	}
}

func TestPlanScheduleKeepsReaddedOrAdjacentRule(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 2},
	}
	reverts, applies := planSchedule(applied, desired)
	if len(reverts) != 0 || len(applies) != 0 {
		t.Fatalf("re-added/adjacent rule churned: reverts=%+v applies=%+v", reverts, applies)
	}
}

func TestPlanScheduleRevertsRemovedMAC(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	reverts, applies := planSchedule(applied, map[string]desiredSched{})
	if len(reverts) != 1 || reverts[0].mac != "AA" {
		t.Fatalf("reverts = %+v", reverts)
	}
	if len(applies) != 0 {
		t.Fatalf("applies = %+v", applies)
	}
}

func TestPlanScheduleRevertsThenAppliesOnIPChange(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "throttle", speed: 64, ip: "192.168.1.5", id: 1},
	}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "throttle", speed: 64, ip: "192.168.1.6", id: 1},
	}
	reverts, applies := planSchedule(applied, desired)
	if len(reverts) != 1 || reverts[0].ip != "192.168.1.5" {
		t.Fatalf("reverts = %+v", reverts)
	}
	if len(applies) != 1 || applies[0].ip != "192.168.1.6" {
		t.Fatalf("applies = %+v", applies)
	}
}

func TestAppliedStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sched-state.json")
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
		"BB": {mac: "BB", action: "throttle", speed: 64, ip: "192.168.1.6", id: 2},
	}
	if err := saveAppliedState(path, applied); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("state mode = %o, want 600", perm)
	}
	loaded := loadAppliedState(path)
	if len(loaded) != 2 {
		t.Fatalf("loaded = %+v", loaded)
	}
	got, ok := loaded["AA"]
	if !ok || got.action != "block" || got.id != 1 {
		t.Fatalf("loaded AA = %+v, ok=%v", got, ok)
	}
	if _, ok := loaded["BB"]; !ok {
		t.Fatal("scheduled throttle entry was not persisted")
	}
}
