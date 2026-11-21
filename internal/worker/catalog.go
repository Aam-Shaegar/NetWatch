package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"netwatch.local/netwatch/internal/catalog"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/store"
)

func (w *Worker) processCatalog(ctx context.Context, j store.Job) error {
	var window contract.Window
	if err := json.Unmarshal(j.Window, &window); err != nil {
		return err
	}
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	passed, err := w.Store.CatalogGatePassed(read, j)
	if err != nil {
		cancel()
		return err
	}
	if !passed {
		if err := w.Store.RegisterCatalogPolicy(read, j.PolicyVersion, w.rules.Settings()); err != nil {
			cancel()
			return err
		}
		var history []contract.Window
		if catalog.Eligible(window) {
			history, err = w.Store.CatalogHistory(read, window)
		}
		cancel()
		if err != nil {
			return err
		}
		decision := w.rules.Evaluate(window, history)
		save, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := w.Store.RecordCatalog(save, j, window, decision, nil)
		cancel()
		if err != nil || decision.Status != catalog.NoMatch {
			if err == nil && w.Log != nil && decision.Status == catalog.Incident {
				w.Log("rule_incident_saved", j.EventID)
			}
			return err
		}
	} else {
		cancel()
	}

	decision, details, inferErr := w.inferCatalog(ctx, j)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	save, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if inferErr != nil {
		if w.Log != nil {
			w.Log("inference_retry", inferErr.Error())
		}
		return w.Store.Retry(save, j, retryDelay(j.Attempts), inferErr.Error())
	}
	if err := w.Store.RecordCatalog(save, j, window, decision, details); err != nil {
		return err
	}
	if w.Log != nil && decision.Status == catalog.Incident {
		w.Log("ml_incident_saved", j.EventID)
	}
	return nil
}

func (w *Worker) inferCatalog(ctx context.Context, j store.Job) (catalog.Decision, json.RawMessage, error) {
	bad := func(reason string) (catalog.Decision, json.RawMessage, error) {
		return catalog.Decision{}, nil, fmt.Errorf("%s", reason)
	}
	raw, err := json.Marshal(struct {
		SchemaVersion int             `json:"schema_version"`
		ModelID       string          `json:"model_id"`
		Window        json.RawMessage `json:"window"`
	}{1, j.ModelID, j.Window})
	if err != nil {
		return bad("invalid_catalog_request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.config.CatalogEndpoint, bytes.NewReader(raw))
	if err != nil {
		return bad("invalid_catalog_request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return bad("catalog_ml_connection_or_timeout")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return bad(fmt.Sprintf("catalog_ml_http_%d", resp.StatusCode))
	}
	result, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(result) > 64<<10 {
		return bad("invalid_catalog_response")
	}
	var p struct {
		SchemaVersion int      `json:"schema_version"`
		EventID       string   `json:"event_id"`
		ModelID       string   `json:"model_id"`
		FeatureSet    string   `json:"feature_set_version"`
		Status        string   `json:"status"`
		Score         *float64 `json:"score"`
		Threshold     *float64 `json:"threshold"`
		AttackType    *string  `json:"attack_type"`
	}
	if json.Unmarshal(result, &p) != nil || p.SchemaVersion != 1 || p.EventID != j.EventID ||
		p.ModelID != j.ModelID || p.FeatureSet != catalog.FeatureSet {
		return bad("catalog_ml_identity_mismatch")
	}
	decision := catalog.Decision{EventID: j.EventID, Source: "ml", DetectorVersion: j.ModelID, AttackType: p.AttackType}
	switch p.Status {
	case "anomalous":
		if p.Score == nil || p.Threshold == nil || p.AttackType == nil ||
			(!catalog.KnownType(*p.AttackType) && *p.AttackType != catalog.Unknown) {
			return bad("invalid_catalog_response")
		}
		decision.Status = catalog.Incident
	case catalog.Normal:
		if p.Score == nil || p.Threshold == nil || p.AttackType != nil {
			return bad("invalid_catalog_response")
		}
		decision.Status = catalog.Normal
	case catalog.Insufficient:
		if p.Score != nil || p.Threshold != nil || p.AttackType != nil {
			return bad("invalid_catalog_response")
		}
		decision.Status = catalog.Insufficient
		decision.Reason = "model_measurement_unusable"
	default:
		return bad("invalid_catalog_response")
	}
	return decision, result, nil
}
