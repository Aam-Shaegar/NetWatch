package worker

import (
	"context"
	"errors"
	"strconv"
	"time"

	"netwatch.local/netwatch/internal/assessment"
)

func (w *Worker) runAssessments(ctx context.Context) {
	for ctx.Err() == nil {
		worked, err := w.assessOnce(ctx)
		if err != nil && w.Log != nil && ctx.Err() == nil {
			w.Log("assessment_storage_unavailable", "retrying")
		}
		if err != nil || !worked {
			timer := time.NewTimer(w.config.Poll)
			select {
			case <-ctx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
	}
}

func (w *Worker) assessOnce(ctx context.Context) (bool, error) {
	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	job, err := w.Store.ClaimAssessment(claimCtx, w.config.Lease)
	cancel()
	if err != nil || job == nil {
		return false, err
	}
	result, err := w.security.Assess(ctx, job.Observation)
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err != nil {
		return true, w.Store.RetryAssessment(dbCtx, *job, retryDelay(int64(job.Attempts)), err.Error(), errors.Is(err, assessment.ErrRejected))
	}
	err = w.Store.FinishAssessment(dbCtx, *job, result)
	if err == nil && w.Log != nil {
		w.Log("assessment_saved", strconv.FormatInt(job.ID, 10))
	}
	return true, err
}
