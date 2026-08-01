package workers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/nicolasparada/ghapp-demo/server/internal/githubapp"
	"github.com/nicolasparada/ghapp-demo/server/internal/postgres"
	"github.com/nicolasparada/ghapp-demo/server/internal/types"
)

type PullConfig struct {
	RetentionWindow time.Duration
	EnrichmentBatch int
}

type PullRunner struct {
	Store  *postgres.Store
	GitHub *githubapp.Client
	Cfg    PullConfig
}

// Start runs all pull workers in a loop, once per interval, until ctx is cancelled.
// It runs an immediate pass on startup, then waits for the interval before repeating.
func (r *PullRunner) Start(ctx context.Context, interval time.Duration) {
	if r.Store == nil || r.GitHub == nil {
		log.Println("pull workers disabled: missing store or github client")
		return
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	r.init()
	for {
		if err := r.RunAll(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("pull workers error: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (r *PullRunner) init() {
	if r.Cfg.RetentionWindow <= 0 {
		r.Cfg.RetentionWindow = 30 * 24 * time.Hour
	}
	if r.Cfg.EnrichmentBatch <= 0 {
		r.Cfg.EnrichmentBatch = 100
	}
}

func (r *PullRunner) RunAll(ctx context.Context) error {

	if err := r.runCoverageSync(ctx); err != nil {
		return fmt.Errorf("coverage sync: %w", err)
	}
	if err := r.runVisibilitySync(ctx); err != nil {
		return fmt.Errorf("visibility sync: %w", err)
	}
	if err := r.runBindingRevalidation(ctx); err != nil {
		return fmt.Errorf("binding revalidation: %w", err)
	}
	if err := r.runRetentionPurge(ctx); err != nil {
		return fmt.Errorf("retention purge: %w", err)
	}
	if err := r.runJobEnrichment(ctx); err != nil {
		return fmt.Errorf("job enrichment: %w", err)
	}
	return nil
}

func (r *PullRunner) runVisibilitySync(ctx context.Context) error {
	repos, err := r.Store.ListReposForSync(ctx)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		owner, name := splitRepoFullName(repo.FullName)
		if owner == "" || name == "" {
			continue
		}
		installationID, err := r.Store.GetAnyInstallationIDForRepo(ctx, repo.RepoID)
		if err != nil {
			return err
		}
		updated, err := r.GitHub.GetRepository(ctx, owner, name, installationID)
		if err != nil {
			log.Printf("visibility sync repo %s: %v", repo.FullName, err)
			continue
		}
		if err := r.Store.UpsertRepo(ctx, types.Repo{
			RepoID:      updated.RepoID,
			FullName:    updated.FullName,
			Owner:       updated.Owner,
			OwnerID:     updated.OwnerID,
			Visibility:  updated.Visibility,
			UpdatedFrom: "api",
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *PullRunner) runCoverageSync(ctx context.Context) error {
	installations, _, notModified, err := r.GitHub.ListAppInstallations(ctx, "")
	if err != nil {
		return err
	}
	if notModified {
		return nil
	}

	keepIDs := make([]int64, 0, len(installations))
	for _, inst := range installations {
		if err := r.Store.UpsertInstallationFromPull(ctx, inst.ID, inst.AccountID, inst.AccountType, inst.AccountLogin, inst.RepositorySelection, false); err != nil {
			return err
		}
		keepIDs = append(keepIDs, inst.ID)

		repoItems, _, _, err := r.GitHub.ListInstallationRepositories(ctx, inst.ID, "")
		if err != nil {
			return err
		}
		repos := make([]types.Repo, 0, len(repoItems))
		for _, item := range repoItems {
			repo := types.Repo{RepoID: item.RepoID, FullName: item.FullName, Owner: item.Owner, OwnerID: item.OwnerID, Visibility: item.Visibility, UpdatedFrom: "api"}
			repos = append(repos, repo)
			if err := r.Store.UpsertRepo(ctx, repo); err != nil {
				return err
			}
		}
		if err := r.Store.ReplaceInstallationRepos(ctx, inst.ID, repos); err != nil {
			return err
		}
	}
	if err := r.Store.MarkInstallationsMissingFromPullDeleted(ctx, keepIDs); err != nil {
		return err
	}

	repoIDs, err := r.Store.ListRepoCoverageCandidates(ctx)
	if err != nil {
		return err
	}
	for _, repoID := range repoIDs {
		installationID, err := r.Store.GetAnyInstallationIDForRepo(ctx, repoID)
		if err != nil {
			return err
		}
		if err := r.Store.UpsertRepoCoverage(ctx, repoID, installationID); err != nil {
			return err
		}
	}
	return nil
}

func (r *PullRunner) runBindingRevalidation(ctx context.Context) error {
	_, err := r.Store.RevokeUncoveredProjectBindings(ctx)
	return err
}

func (r *PullRunner) runRetentionPurge(ctx context.Context) error {
	_, err := r.Store.PurgeUnretainedRuns(ctx, r.Cfg.RetentionWindow)
	return err
}

func (r *PullRunner) runJobEnrichment(ctx context.Context) error {
	groups, err := r.Store.ListPendingEnrichmentGroups(ctx, r.Cfg.EnrichmentBatch)
	if err != nil {
		return err
	}
	for _, g := range groups {
		installationID, err := r.Store.GetAnyInstallationIDForRepo(ctx, g.RepoID)
		if err != nil {
			return err
		}
		runs, err := r.Store.ListRunsForEnrichmentGroup(ctx, g.RepoID, g.RunID, g.RunAttempt)
		if err != nil {
			return err
		}
		if installationID == nil {
			for _, run := range runs {
				if err := r.Store.MarkRunEnrichmentUnavailable(ctx, run.ID); err != nil {
					return err
				}
			}
			continue
		}

		jobs, err := r.GitHub.ListRunAttemptJobs(ctx, g.Owner, g.RepoName, g.RunID, g.RunAttempt, *installationID)
		if err != nil {
			for _, run := range runs {
				if err := r.Store.MarkRunEnrichmentUnavailable(ctx, run.ID); err != nil {
					return err
				}
			}
			continue
		}

		matched, ambiguous := matchJobsToRuns(runs, jobs)
		for _, runID := range ambiguous {
			if err := r.Store.MarkRunEnrichmentAmbiguous(ctx, runID); err != nil {
				return err
			}
		}
		for runID, job := range matched {
			if err := r.Store.MarkRunEnrichmentMatched(ctx, runID, job.ID, job.Name, job.Conclusion, job.StartedAt, job.CompletedAt); err != nil {
				return err
			}
		}
	}
	return nil
}

func matchJobsToRuns(runs []postgres.EnrichmentRunRow, jobs []githubapp.RunJob) (map[int64]githubapp.RunJob, []int64) {
	type candidate struct {
		runID int64
		job   githubapp.RunJob
	}
	chosen := make([]candidate, 0, len(runs))
	jobToRuns := map[int64][]int64{}
	ambiguousSet := map[int64]struct{}{}

	for _, run := range runs {
		matches := make([]githubapp.RunJob, 0, 2)
		for _, job := range jobs {
			if !strings.EqualFold(strings.TrimSpace(run.RunnerName), strings.TrimSpace(job.RunnerName)) {
				continue
			}
			if run.CaptureStartedAt == nil || run.CaptureEndedAt == nil || job.StartedAt == nil || job.CompletedAt == nil {
				continue
			}
			start := job.StartedAt.Add(-60 * time.Second)
			end := job.CompletedAt.Add(60 * time.Second)
			if run.CaptureStartedAt.Before(start) || run.CaptureEndedAt.After(end) {
				continue
			}
			matches = append(matches, job)
		}
		if len(matches) == 1 {
			chosen = append(chosen, candidate{runID: run.ID, job: matches[0]})
			jobToRuns[matches[0].ID] = append(jobToRuns[matches[0].ID], run.ID)
			continue
		}
		ambiguousSet[run.ID] = struct{}{}
	}

	matched := map[int64]githubapp.RunJob{}
	for _, c := range chosen {
		if len(jobToRuns[c.job.ID]) != 1 {
			ambiguousSet[c.runID] = struct{}{}
			continue
		}
		matched[c.runID] = c.job
	}

	ambiguous := make([]int64, 0, len(ambiguousSet))
	for runID := range ambiguousSet {
		ambiguous = append(ambiguous, runID)
	}
	return matched, ambiguous
}

func splitRepoFullName(fullName string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(fullName), "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
