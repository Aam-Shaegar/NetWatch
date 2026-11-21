package pipeline_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			Window  contract.Window `json:"window"`
		}
		if r.URL.Path != "/v1/detect" || json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "invalid test request", 400)
			return
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
