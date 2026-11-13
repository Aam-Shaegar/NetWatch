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
	"time"

	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/store"
)

type Request struct {
	SchemaVersion int               `json:"schema_version"`
	ModelID       string            `json:"model_id"`
	PolicyVersion string            `json:"policy_version"`
	Windows       []json.RawMessage `json:"windows"`
}
type Response struct {
	SchemaVersion int                   `json:"schema_version"`
	Predictions   []contract.Prediction `json:"predictions"`
}
type Config struct {
	Endpoint             string
	Lease, Timeout, Poll time.Duration
	AllowInsecureHTTP    bool
}

func DefaultConfig() Config {
	return Config{Endpoint: "http://127.0.0.1:8000/v1/predict", Lease: 30 * time.Second, Timeout: 10 * time.Second, Poll: 250 * time.Millisecond}
}

type Worker struct {
	Store  *store.Store
	config Config
	client *http.Client
	claims uint64
	Log    func(string, string)
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
	if u.Scheme == "http" && !local && !c.AllowInsecureHTTP {
		return nil, fmt.Errorf("remote ML requires HTTPS or explicit isolated-lab HTTP")
	}
	if s == nil || c.Timeout <= 0 || c.Lease < 2*c.Timeout || c.Lease > time.Hour || c.Poll <= 0 {
		return nil, fmt.Errorf("lease must cover at least two HTTP timeouts")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxResponseHeaderBytes = 64 << 10
	return &Worker{Store: s, config: c, client: &http.Client{Timeout: c.Timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (w *Worker) Infer(ctx context.Context, j store.Job) (contract.Prediction, error) {
	body, err := json.Marshal(Request{1, j.ModelID, j.PolicyVersion, []json.RawMessage{j.Window}})
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
	if p.EventID != j.EventID || p.ModelID != j.ModelID || p.FeatureSetVersion != "traffic-v1" {
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
		ceiling := time.Second
		for i := int64(1); i < j.Attempts && ceiling < 60*time.Second; i++ {
			ceiling *= 2
		}
		ceiling = min(ceiling, 60*time.Second)
		delay := ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)))
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
	for ctx.Err() == nil {
		worked, err := w.Once(ctx)
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
