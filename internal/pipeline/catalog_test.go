package pipeline_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"netwatch.local/netwatch/internal/catalog"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/worker"
)

func TestCatalogGatePersistsTypedAndUnknownIncidents(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	var calls atomic.Int32
	ml := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ModelID string          `json:"model_id"`
			History json.RawMessage `json:"history"`
			Window  contract.Window `json:"window"`
		}
		if r.URL.Path != "/v1/detect" || json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "invalid test request", 400)
			return
		}
		if req.History != nil {
			t.Error("base model received temporal history")
		}
		if calls.Add(1) == 1 {
			http.Error(w, "unavailable", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": 1, "model_id": req.ModelID, "event_id": req.Window.EventID, "feature_set_version": catalog.FeatureSet,
			"status": "anomalous", "attack_type": "unknown", "score": 0.8, "threshold": 0.7,
		})
	}))
	defer ml.Close()
	cfg := worker.DefaultConfig()
	cfg.CatalogEndpoint = ml.URL + "/v1/detect"
	runner, err := worker.New(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Truncate(time.Second).Add(-time.Minute)
	ingest := func(id string, offset time.Duration, ports float64, measured bool) {
		t.Helper()
		var modelWindow contract.Window
		if err := json.Unmarshal(window(t, id, base.Add(offset)), &modelWindow); err != nil {
			t.Fatal(err)
		}
		modelWindow.FeatureSetVersion = catalog.FeatureSet
		modelWindow.EntityType = "host"
		zero, packets := float64(0), float64(100)
		for k, v := range map[string]*float64{
			"in_packets": &packets, "in_tcp_distinct_ports_per_source_max": &ports,
			"in_udp_packets": &zero, "in_icmp_packets": &zero, "in_udp_ip_bytes": &zero, "in_icmp_ip_bytes": &zero,
		} {
			modelWindow.Features[k] = v
		}
		if measured {
			noDrops := int64(0)
			modelWindow.Quality.CaptureDropped = &noDrops
		}
		raw, err := json.Marshal(modelWindow)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Ingest(ctx, batch(t, raw), sensor, "catalog-test", "v1"); err != nil {
			t.Fatal(err)
		}
		worked, err := runner.Once(ctx)
		if err != nil || !worked {
			t.Fatalf("process %s: %v %v", id, worked, err)
		}
	}

	ingest("scan-old", 5*time.Second, 40, true)
	ingest("scan-new", 25*time.Second, 40, true)
	ingest("scan-bridge", 15*time.Second, 40, true)
	ingest("loss", 30*time.Second, 40, false)
	if calls.Load() != 0 {
		t.Fatal("ML was called for rule match or unusable capture")
	}
	ingest("unknown", 35*time.Second, 0, true)
	var gate string
	if err := db.Pool.QueryRow(ctx, `SELECT status FROM catalog_decisions WHERE event_id='unknown'`).Scan(&gate); err != nil || gate != catalog.NoMatch {
		t.Fatalf("ML failure discarded rule gate: %v %v", gate, err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE inference_jobs SET available_at=clock_timestamp() WHERE event_id='unknown'`); err != nil {
		t.Fatal(err)
	}
	worked, err := runner.Once(ctx)
	if err != nil || !worked || calls.Load() != 2 {
		t.Fatalf("retry: %v %v ML calls=%d", worked, err, calls.Load())
	}

	raw, err := db.CatalogIncidents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Total     int            `json:"total"`
		ByType    map[string]int `json:"by_type"`
		BySource  map[string]int `json:"by_source"`
		Incidents []struct {
			Type  string `json:"type"`
			First string `json:"first_ns"`
			Last  string `json:"last_ns"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Total != 2 || result.ByType["tcp_port_scan"] != 1 ||
		result.ByType["unknown"] != 1 || result.BySource["rules"] != 1 || result.BySource["ml"] != 1 || len(result.Incidents) != 2 {
		t.Fatalf("incorrect aggregation %s: %v", raw, err)
	}
	if scan := result.Incidents[1]; scan.Type != "tcp_port_scan" || scan.First != strconv.FormatInt(base.UnixNano(), 10) ||
		scan.Last != strconv.FormatInt(base.Add(25*time.Second).UnixNano(), 10) {
		t.Fatalf("incorrect windows after merging late bridge: %+v", scan)
	}
}

func TestCatalogTemporalHistorySurvivesRetryAndLateIngress(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	var calls atomic.Int32
	ml := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ModelID string            `json:"model_id"`
			Window  contract.Window   `json:"window"`
			History []contract.Window `json:"history"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			http.Error(w, "bad request", 400)
			return
		}
		var ids []string
		for _, prior := range input.History {
			ids = append(ids, prior.EventID)
		}
		if !slices.Equal(ids, []string{"rule", "unusable", "prior", "adjacent"}) ||
			input.ModelID != catalog.TemporalModelID || input.Window.EventID != "target" {
			t.Errorf("unexpected temporal input %s/%s %v", input.ModelID, input.Window.EventID, ids)
		}
		if calls.Add(1) == 1 {
			http.Error(w, "retry", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema_version": 1, "model_id": input.ModelID, "event_id": input.Window.EventID,
			"feature_set_version": catalog.FeatureSet, "status": "anomalous", "attack_type": "unknown",
			"score": 1, "threshold": 0.9978790881906234, "detector_stage": "temporal",
		})
	}))
	defer ml.Close()
	cfg := worker.DefaultConfig()
	cfg.CatalogEndpoint = ml.URL + "/v1/detect"
	base := time.Now().Truncate(5 * time.Second).Add(-time.Minute)
	ingest := func(id string, seconds int, entity, epoch string) {
		t.Helper()
		var w contract.Window
		if err := json.Unmarshal(window(t, id, base.Add(time.Duration(seconds)*time.Second)), &w); err != nil {
			t.Fatal(err)
		}
		w.FeatureSetVersion, w.EntityType, w.EntityID, w.CaptureEpoch = catalog.FeatureSet, "host", entity, epoch
		noDrops := int64(0)
		w.Quality.CaptureDropped = &noDrops
		if id == "unusable" {
			w.Quality.CaptureDropped = nil
		}
		ports, packets, zero := float64(1), float64(100), float64(0)
		if id == "rule" {
			ports = 50
		}
		w.Features["in_tcp_distinct_ports_per_source_max"] = &ports
		w.Features["in_packets"], w.Features["in_udp_packets"], w.Features["in_icmp_packets"] = &packets, &zero, &zero
		w.Features["in_udp_ip_bytes"], w.Features["in_icmp_ip_bytes"] = &zero, &zero
		raw, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Ingest(ctx, batch(t, raw), sensor, catalog.TemporalModelID, "v1"); err != nil {
			t.Fatal(err)
		}
	}
	ingest("old", 5, "target", "epoch-a")
	ingest("rule", 15, "target", "epoch-a")
	ingest("unusable", 20, "target", "epoch-a")
	ingest("prior", 25, "target", "epoch-a")
	ingest("another-entity", 30, "other", "epoch-a")
	ingest("another-epoch", 30, "target", "epoch-b")
	ingest("adjacent", 30, "target", "epoch-a")
	ingest("target", 35, "target", "epoch-a")
	process := func() {
		t.Helper()
		// Both workers see the target first (the newest window). Its predecessors
		// are still pending; the second worker has no in-process history.
		runner, err := worker.New(db, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if worked, err := runner.Once(ctx); err != nil || !worked {
			t.Fatalf("temporal worker: %v %v", worked, err)
		}
	}
	process()
	ingest("late", 10, "target", "epoch-a")
	if _, err := db.Pool.Exec(ctx, `UPDATE inference_jobs SET available_at=clock_timestamp() WHERE event_id='target'`); err != nil {
		t.Fatal(err)
	}
	process()
	var status, stage string
	if err := db.Pool.QueryRow(ctx, `SELECT status,payload->'details'->>'detector_stage' FROM catalog_decisions WHERE event_id='target'`).Scan(&status, &stage); err != nil || calls.Load() != 2 || status != catalog.Incident || stage != "temporal" {
		t.Fatalf("temporal ML result %s/%s calls=%d: %v", status, stage, calls.Load(), err)
	}
}
