// Package worker runs leased inference jobs without holding database locks during HTTP.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netwatch.local/netwatch/internal/assessment"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/store"
)

type Request struct {
	Histories     map[string][]json.RawMessage `json:"histories,omitempty"`
	SchemaVersion int                          `json:"schema_version"`
	ModelID       string                       `json:"model_id"`
	PolicyVersion string                       `json:"policy_version"`
	Windows       []json.RawMessage            `json:"windows"`
}
type Response struct {
	SchemaVersion int                   `json:"schema_version"`
	Predictions   []contract.Prediction `json:"predictions"`
}
type Config struct {
	Endpoint, SecurityEndpoint        string
	Lease, Timeout, Poll, GapWait     time.Duration
	AllowInsecureHTTP, PrivateCompose bool
}

func DefaultConfig() Config {
	return Config{Endpoint: "http://127.0.0.1:8000/v1/predict", Lease: 30 * time.Second, Timeout: 10 * time.Second, Poll: 250 * time.Millisecond}
}

type Worker struct {
	Store    *store.Store
	config   Config
	client   *http.Client
	security *assessment.Client
	claims   uint64
	Log      func(string, string)
}

func New(s *store.Store, c Config) (*Worker, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid ML endpoint")
	}
	local := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		local = ip.IsLoopback()
	}
	if u.Scheme == "http" && !local && !c.AllowInsecureHTTP && !assessment.ValidEndpoint(c.Endpoint, "/v1/predict", c.PrivateCompose) {
		return nil, fmt.Errorf("remote ML requires HTTPS or explicit isolated-lab HTTP")
	}
	if s == nil || c.Timeout <= 0 || c.Lease < 2*c.Timeout || c.Lease > time.Hour || c.Poll <= 0 || c.GapWait < 0 {
		return nil, fmt.Errorf("lease must cover at least two HTTP timeouts")
	}
	if c.SecurityEndpoint != "" && !assessment.ValidEndpoint(c.SecurityEndpoint, "/v1/security/assess", c.PrivateCompose) {
		return nil, fmt.Errorf("invalid assessment endpoint")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxResponseHeaderBytes = 64 << 10
	return &Worker{Store: s, config: c, security: assessment.New(c.SecurityEndpoint, c.Timeout), client: &http.Client{Timeout: c.Timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (w *Worker) Infer(ctx context.Context, j store.Job) (contract.Prediction, error) {
	var window struct {
		Version string `json:"feature_set_version"`
	}
	if json.Unmarshal(j.Window, &window) != nil || !contract.IsTrafficFeatureSet(window.Version) {
		return contract.Prediction{}, fmt.Errorf("invalid_window_feature_set")
	}
	input := Request{SchemaVersion: 1, ModelID: j.ModelID, PolicyVersion: j.PolicyVersion, Windows: []json.RawMessage{j.Window}}
	if strings.HasPrefix(j.ModelID, "gru-") {
		past, err := w.Store.ForecastHistory(ctx, j.EventID)
		if err != nil {
			return contract.Prediction{}, fmt.Errorf("forecast_history_unavailable")
		}
		input.Histories = map[string][]json.RawMessage{j.EventID: past}
	}
	body, err := json.Marshal(input)
	if err != nil {
		return contract.Prediction{}, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", w.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return contract.Prediction{}, fmt.Errorf("invalid_inference_request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return contract.Prediction{}, fmt.Errorf("ml_connection_or_timeout")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 409 || resp.StatusCode == 422 {
		var rejected struct{ Error string }
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1025))
		if readErr == nil && len(raw) <= 1024 && json.Unmarshal(raw, &rejected) == nil &&
			(resp.StatusCode == 409 && rejected.Error == "incompatible_model_or_policy" || resp.StatusCode == 422 && rejected.Error == "invalid_inference_request") {
			return contract.Prediction{SchemaVersion: 1, FeatureSetVersion: window.Version, ModelID: j.ModelID, EventID: j.EventID, Status: "error", Reason: rejected.Error}, nil
		}
	}
	if resp.StatusCode != 200 {
		return contract.Prediction{}, fmt.Errorf("ml_http_%d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return contract.Prediction{}, fmt.Errorf("ml_response_size_or_read")
	}
	if contract.Validate("inference-response", raw) != nil {
		return contract.Prediction{}, fmt.Errorf("ml_invalid_response")
	}
	var result Response
	if json.Unmarshal(raw, &result) != nil || len(result.Predictions) != 1 {
		return contract.Prediction{}, fmt.Errorf("ml_invalid_response")
	}
	p := result.Predictions[0]
	if p.EventID != j.EventID || p.ModelID != j.ModelID || p.FeatureSetVersion != window.Version {
		return p, fmt.Errorf("ml_identity_mismatch")
	}
	// A transient model error is not a completed inference job.
	if p.Status == "error" {
		return p, fmt.Errorf("ml_error_status")
	}
	return p, nil
}

// Once processes at most one job. Every fifth claim reserves a turn for old backlog.
func (w *Worker) Once(ctx context.Context) (bool, error) {
	dbctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	j, err := w.Store.Claim(dbctx, w.config.Lease, (w.claims+1)%5 == 0)
	cancel()
	if err != nil || j == nil {
		return false, err
	}
	w.claims++
	p, inferErr := w.Infer(ctx, *j)
	if ctx.Err() != nil {
		return true, ctx.Err()
	} // Leave the lease to expire after shutdown.
	dbctx, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if inferErr != nil {
		delay := retryDelay(j.Attempts)
		err = w.Store.Retry(dbctx, *j, delay, inferErr.Error())
		if w.Log != nil {
			w.Log("inference_retry", inferErr.Error())
		}
	} else {
		err = w.Store.Finish(dbctx, *j, p)
		if err == nil && w.Log != nil {
			w.Log("prediction_saved", j.EventID)
		}
	}
	if errors.Is(err, store.ErrLeaseLost) {
		if w.Log != nil {
			w.Log("lease_lost", j.EventID)
		}
		return true, nil
	}
	return true, err
}
func (w *Worker) Run(ctx context.Context) error {
	defer w.client.CloseIdleConnections()
	defer w.security.Close()
	assessmentDone := make(chan struct{})
	go func() {
		defer close(assessmentDone)
		w.runAssessments(ctx)
	}()
	defer func() { <-assessmentDone }()
	for ctx.Err() == nil {
		worked, err := w.Once(ctx)
		projectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		advanced, projectErr := w.Store.ProjectWithGap(projectCtx, w.config.GapWait)
		cancel()
		worked = worked || advanced
		if err == nil {
			err = projectErr
		}
		if ctx.Err() != nil {
			break
		}
		if err != nil && w.Log != nil {
			w.Log("worker_storage_unavailable", "retrying")
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
	return nil
}

func retryDelay(attempts int64) time.Duration {
	ceiling := time.Second
	for i := int64(1); i < attempts && ceiling < 60*time.Second; i++ {
		ceiling *= 2
	}
	ceiling = min(ceiling, 60*time.Second)
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)))
}
