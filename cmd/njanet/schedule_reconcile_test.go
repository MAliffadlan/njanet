package main

import (
	"fmt"
	"testing"

	"github.com/mectov/njanet/internal/db"
)

type fakeSchedCtrl struct {
	calls      []string
	active     map[string]bool
	manual     map[string]bool
	blockErr   error
	unblockErr error
	events     *[]string
}

func (f *fakeSchedCtrl) BlockDeviceScheduled(dev *db.Device) error {
	f.calls = append(f.calls, "block-sched:"+dev.IP)
	if f.events != nil {
		*f.events = append(*f.events, "apply")
	}
	return f.blockErr
}

func (f *fakeSchedCtrl) ThrottleDevice(dev *db.Device, speed int) error {
	f.calls = append(f.calls, fmt.Sprintf("throttle:%s:%d", dev.IP, speed))
	return nil
}

func (f *fakeSchedCtrl) UnblockScheduled(dev *db.Device) error {
	f.calls = append(f.calls, "unblock-sched:"+dev.IP)
	return f.unblockErr
}

func (f *fakeSchedCtrl) ScheduledBlockActive(mac, ip string) bool {
	return f.active[ip]
}

func (f *fakeSchedCtrl) ManualBlockRulesExist(ip string) bool {
	return f.manual[ip]
}

func TestReconcileKeepsReaddedBlock(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 2},
	}
	ctrl := &fakeSchedCtrl{active: map[string]bool{"192.168.1.5": true}}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, func() error { return nil })

	if len(ctrl.calls) != 0 {
		t.Fatalf("re-added block churned: %v", ctrl.calls)
	}
	if got := applied["AA"]; got.id != 2 {
		t.Fatalf("applied = %+v", got)
	}
}

func TestReconcileRevertsScheduledBlock(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{active: map[string]bool{"192.168.1.5": true}}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, map[string]desiredSched{}, func() error { return nil })

	if len(ctrl.calls) != 1 || ctrl.calls[0] != "unblock-sched:192.168.1.5" {
		t.Fatalf("calls = %v", ctrl.calls)
	}
	if len(applied) != 0 {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcileAppliesScheduledBlock(t *testing.T) {
	applied := map[string]appliedSched{}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, func() error { return nil })

	if len(ctrl.calls) != 1 || ctrl.calls[0] != "block-sched:192.168.1.5" {
		t.Fatalf("calls = %v", ctrl.calls)
	}
	if _, ok := applied["AA"]; !ok {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcileReappliesInactiveBlock(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{
		active: map[string]bool{"192.168.1.5": false},
	}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, func() error { return nil })

	want := []string{"unblock-sched:192.168.1.5", "block-sched:192.168.1.5"}
	if fmt.Sprint(ctrl.calls) != fmt.Sprint(want) {
		t.Fatalf("calls = %v, want %v", ctrl.calls, want)
	}
	if _, ok := applied["AA"]; !ok {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcileKeepsDBBlockedForManualOwner(t *testing.T) {
	d := testTargetDB(t)
	if _, err := d.UpsertDevice(&db.Device{
		MAC: "AA:BB:CC:DD:EE:FF", IP: "192.168.1.5", Online: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.UpdateDeviceBlock("AA:BB:CC:DD:EE:FF", true); err != nil {
		t.Fatal(err)
	}
	applied := map[string]appliedSched{
		"AA:BB:CC:DD:EE:FF": {
			mac: "AA:BB:CC:DD:EE:FF", action: "block", ip: "192.168.1.5", id: 1,
		},
	}
	ctrl := &fakeSchedCtrl{
		active: map[string]bool{"192.168.1.5": true},
		manual: map[string]bool{"192.168.1.5": true},
	}

	reconcileScheduleState(ctrl, d, applied, map[string]desiredSched{}, func() error { return nil })

	devices, err := d.GetAllDevices()
	if err != nil || len(devices) != 1 {
		t.Fatalf("GetAllDevices = %d, %v", len(devices), err)
	}
	if !devices[0].Blocked {
		t.Fatal("DB blocked flag cleared while a manual block still owns the IP")
	}
}

func TestReconcileRepairsWhenCleanupFails(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{
		active:     map[string]bool{"192.168.1.5": false},
		unblockErr: fmt.Errorf("iptables busy"),
	}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, func() error { return nil })

	want := []string{"unblock-sched:192.168.1.5", "block-sched:192.168.1.5"}
	if fmt.Sprint(ctrl.calls) != fmt.Sprint(want) {
		t.Fatalf("calls = %v, want %v", ctrl.calls, want)
	}
	if _, ok := applied["AA"]; !ok {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcileToleratesDBFailureOnRevert(t *testing.T) {
	d := testTargetDB(t)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{active: map[string]bool{"192.168.1.5": true}}

	reconcileScheduleState(ctrl, d, applied, map[string]desiredSched{}, func() error { return nil })

	if len(ctrl.calls) != 1 || ctrl.calls[0] != "unblock-sched:192.168.1.5" {
		t.Fatalf("calls = %v", ctrl.calls)
	}
	if len(applied) != 0 {
		t.Fatalf("applied retained after successful kernel revert: %+v", applied)
	}
}

func TestReconcileRevertsScheduledThrottle(t *testing.T) {
	applied := map[string]appliedSched{
		"AA": {mac: "AA", action: "throttle", speed: 64, ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, map[string]desiredSched{}, func() error { return nil })

	if len(ctrl.calls) != 1 || ctrl.calls[0] != "throttle:192.168.1.5:0" {
		t.Fatalf("calls = %v", ctrl.calls)
	}
	if len(applied) != 0 {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcileSkipsApplyWhenStateCannotBeSaved(t *testing.T) {
	applied := map[string]appliedSched{}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{}
	fail := func() error { return fmt.Errorf("disk full") }

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, fail)

	if len(ctrl.calls) != 0 {
		t.Fatalf("rule applied without durable state: %v", ctrl.calls)
	}
	if len(applied) != 0 {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcileRevertsWhenFinalStateSaveFails(t *testing.T) {
	applied := map[string]appliedSched{}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{}
	calls := 0
	persist := func() error {
		calls++
		if calls == 3 { // initial, write-ahead, then final
			return fmt.Errorf("disk full")
		}
		return nil
	}

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, persist)

	want := []string{"block-sched:192.168.1.5", "unblock-sched:192.168.1.5"}
	if fmt.Sprint(ctrl.calls) != fmt.Sprint(want) {
		t.Fatalf("calls = %v, want %v", ctrl.calls, want)
	}
	if len(applied) != 0 {
		t.Fatalf("applied = %+v", applied)
	}
}

func TestReconcilePersistsBeforeApply(t *testing.T) {
	var events []string
	applied := map[string]appliedSched{}
	desired := map[string]desiredSched{
		"AA": {mac: "AA", action: "block", ip: "192.168.1.5", id: 1},
	}
	ctrl := &fakeSchedCtrl{events: &events}
	persist := func() error { events = append(events, "persist"); return nil }

	reconcileScheduleState(ctrl, testTargetDB(t), applied, desired, persist)

	applyIdx := -1
	for i, e := range events {
		if e == "apply" {
			applyIdx = i
			break
		}
	}
	if applyIdx <= 0 || events[applyIdx-1] != "persist" {
		t.Fatalf("apply was not preceded by persisted intent: %v", events)
	}
	if events[len(events)-1] != "persist" {
		t.Fatalf("final state was not persisted: %v", events)
	}
}
