package workers

import (
	"testing"
	"time"

	"github.com/nicolasparada/ghapp-demo/server/internal/githubapp"
	"github.com/nicolasparada/ghapp-demo/server/internal/postgres"
)

func TestMatchJobsToRuns_BijectionAndAmbiguous(t *testing.T) {
	now := time.Now().UTC()
	start := now.Add(-10 * time.Minute)
	end := now.Add(-9 * time.Minute)

	runs := []postgres.EnrichmentRunRow{
		{ID: 1, RunnerName: "runner-a", CaptureStartedAt: ptrTime(start.Add(10 * time.Second)), CaptureEndedAt: ptrTime(end.Add(-10 * time.Second))},
		{ID: 2, RunnerName: "runner-a", CaptureStartedAt: ptrTime(start.Add(20 * time.Second)), CaptureEndedAt: ptrTime(end.Add(-20 * time.Second))},
		{ID: 3, RunnerName: "runner-b", CaptureStartedAt: ptrTime(start.Add(10 * time.Second)), CaptureEndedAt: ptrTime(end.Add(-10 * time.Second))},
	}
	jobs := []githubapp.RunJob{
		{ID: 100, Name: "build (ubuntu,1)", RunnerName: "runner-a", StartedAt: ptrTime(start), CompletedAt: ptrTime(end)},
		{ID: 101, Name: "test (ubuntu,2)", RunnerName: "runner-b", StartedAt: ptrTime(start), CompletedAt: ptrTime(end)},
	}

	matched, ambiguous := matchJobsToRuns(runs, jobs)

	if _, ok := matched[3]; !ok {
		t.Fatalf("expected run 3 to be matched")
	}
	if len(matched) != 1 {
		t.Fatalf("expected exactly 1 matched run, got %d", len(matched))
	}

	if !containsRunID(ambiguous, 1) || !containsRunID(ambiguous, 2) {
		t.Fatalf("expected runs 1 and 2 to be ambiguous due to bijection conflict, got %v", ambiguous)
	}
}

func TestMatchJobsToRuns_RequiresWindowAndRunner(t *testing.T) {
	now := time.Now().UTC()
	runs := []postgres.EnrichmentRunRow{
		{ID: 1, RunnerName: "runner-a", CaptureStartedAt: ptrTime(now), CaptureEndedAt: ptrTime(now.Add(2 * time.Minute))},
	}
	jobs := []githubapp.RunJob{
		{ID: 100, RunnerName: "runner-b", StartedAt: ptrTime(now.Add(-1 * time.Minute)), CompletedAt: ptrTime(now.Add(3 * time.Minute))},
	}
	matched, ambiguous := matchJobsToRuns(runs, jobs)
	if len(matched) != 0 {
		t.Fatalf("expected no matches")
	}
	if !containsRunID(ambiguous, 1) {
		t.Fatalf("expected run 1 ambiguous")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func containsRunID(ids []int64, target int64) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
