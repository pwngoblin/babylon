package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSchedulerRunsDueScans(t *testing.T) {
	home := t.TempDir()
	a, err := Open(home)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ctx := context.Background()
	if _, _, err := a.CreateSchedule(ctx, "x", Request{Targets: []string{"127.0.0.1"}}, 5*time.Minute); err == nil {
		t.Error("an interval under 15 minutes must be refused")
	}
	sid, first, err := a.CreateSchedule(ctx, "nightly", Request{Targets: []string{"127.0.0.1"}, MaxHosts: 1}, time.Hour)
	if err != nil || first == 0 || sid == 0 {
		t.Fatalf("create: %v %d %d", err, sid, first)
	}
	var started []int64
	start := func(id int64) error { started = append(started, id); return nil }
	busy := errors.New("busy")

	if n := a.RunDue(ctx, time.Now(), start, busy); n != 0 {
		t.Errorf("not due yet, but %d scans started", n)
	}
	later := time.Now().Add(2 * time.Hour)
	if n := a.RunDue(ctx, later, start, busy); n != 1 || len(started) != 1 || started[0] == first {
		t.Fatalf("due run: n=%d started=%v first=%d", n, started, first)
	}
	if n := a.RunDue(ctx, later, start, busy); n != 0 {
		t.Error("next_run must move forward after a run")
	}
	// Busy: the schedule stays due and is retried.
	later2 := later.Add(2 * time.Hour)
	if n := a.RunDue(ctx, later2, func(int64) error { return busy }, busy); n != 0 {
		t.Error("busy run must not count as started")
	}
	if n := a.RunDue(ctx, later2, start, busy); n != 1 {
		t.Error("a busy schedule must be retried on the next tick")
	}
	// The scope file applies to scheduled runs too.
	os.WriteFile(filepath.Join(home, ScopeFile), []byte("10.9.9.9\n"), 0o600)
	later3 := later2.Add(2 * time.Hour)
	if n := a.RunDue(ctx, later3, start, busy); n != 0 {
		t.Error("a target outside scope must not be scanned by a schedule")
	}
	list, _ := a.St.ListSchedules(ctx)
	if len(list) != 1 || list[0].LastError == "" {
		t.Errorf("the refusal must be recorded: %+v", list)
	}
	// Disabled schedules do not run.
	_ = a.St.SetScheduleEnabled(ctx, sid, false)
	os.Remove(filepath.Join(home, ScopeFile))
	if n := a.RunDue(ctx, later3.Add(5*time.Hour), start, busy); n != 0 {
		t.Error("disabled schedule ran")
	}
}
