package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"babylon/internal/store"
)

// CreateSchedule validates a scan request by creating its first scan (all scope,
// template and target rules apply), then stores the repeat definition. The first
// scan id is returned so the caller can start it; later runs start from next_run.
func (a *App) CreateSchedule(ctx context.Context, name string, req Request, every time.Duration) (scheduleID, firstScan int64, err error) {
	if every < store.MinScheduleMinutes*time.Minute {
		return 0, 0, fmt.Errorf("repeat interval must be at least %d minutes", store.MinScheduleMinutes)
	}
	if every > 366*24*time.Hour {
		return 0, 0, fmt.Errorf("repeat interval must be at most one year")
	}
	if strings.TrimSpace(name) == "" {
		name = req.Name
	}
	if strings.TrimSpace(name) == "" {
		name = "Scheduled scan"
	}
	firstScan, err = a.Create(ctx, req)
	if err != nil {
		return 0, 0, err
	}
	b, _ := json.Marshal(req)
	scheduleID, err = a.St.CreateSchedule(ctx, name, string(b), int(every/time.Minute), time.Now().Add(every))
	return scheduleID, firstScan, err
}

// RunDue creates a scan for every schedule whose time has come. start is called
// with each new scan id; if it reports busy, the schedule is left due and tried
// again on the next tick. Returns how many scans were started.
func (a *App) RunDue(ctx context.Context, now time.Time, start func(id int64) error, busy error) int {
	due, err := a.St.DueSchedules(ctx, now)
	if err != nil {
		return 0
	}
	started := 0
	for _, s := range due {
		var req Request
		if err := json.Unmarshal([]byte(s.Request), &req); err != nil {
			_ = a.St.MarkScheduleRan(ctx, s.ID, now, now.Add(time.Duration(s.IntervalMin)*time.Minute), 0, "stored request is unreadable")
			continue
		}
		next := now.Add(time.Duration(s.IntervalMin) * time.Minute)
		id, err := a.Create(ctx, req)
		if err != nil { // e.g. scope file changed: record, skip this round
			_ = a.St.MarkScheduleRan(ctx, s.ID, now, next, 0, err.Error())
			continue
		}
		if err := start(id); err != nil {
			if err == busy {
				continue // keep due; the created scan stays pending and is resumable
			}
			_ = a.St.MarkScheduleRan(ctx, s.ID, now, next, id, err.Error())
			continue
		}
		_ = a.St.MarkScheduleRan(ctx, s.ID, now, next, id, "")
		started++
	}
	return started
}
