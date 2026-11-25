package pipeline_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"netwatch.local/netwatch/internal/store"
)

func TestPilotStartIsIdempotent(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	if _, err := db.PilotReport(ctx, "campus"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing pilot: got %v", err)
	}
	started, err := db.StartPilot(ctx, "campus", "original", "v1")
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := db.StartPilot(ctx, "campus", "new-model", "v2")
	if err != nil || string(started) != string(repeated) {
		t.Fatalf("repeated start changed the trial: %s then %s (%v)", started, repeated, err)
	}
	raw, err := db.PilotReport(ctx, "campus")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Model  string    `json:"model_id"`
		Policy string    `json:"policy_version"`
		Start  time.Time `json:"started_at"`
		End    time.Time `json:"ends_at"`
		AsOf   time.Time `json:"as_of"`
		Done   bool      `json:"complete"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Done || report.AsOf.Before(report.Start) || !report.AsOf.Before(report.End) ||
		report.End.Sub(report.Start) != 168*time.Hour || report.Model != "original" || report.Policy != "v1" {
		t.Fatalf("invalid running pilot: %s", raw)
	}
}

func TestPilotReportCountsObservationSlotsAndIncidentIDs(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	if _, err := db.StartPilot(ctx, "campus", "selected", "v1"); err != nil {
		t.Fatal(err)
	}
	// The pilot starts one second into a slot. Only fully scheduled slots count.
	start := time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)
	end := start.Add(168 * time.Hour)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE pilots SET started_at=$1 WHERE name='campus'", start)
	exec(`INSERT INTO registered_sensors(id, token_hash, registered_at)
		SELECT id, decode(repeat(key,32),'hex'), registered_at FROM (VALUES
		('online','01',$1::timestamptz), ('silent','02',$1), ('late','03',$2), ('after','04',$3)
		) s(id,key,registered_at)`, start, end.Add(-16*time.Second), end.Add(time.Second))

	// Two event IDs share the first complete slot. The two alert windows also
	// refer to the same incident. A second model's decision is irrelevant.
	base := start.Truncate(5 * time.Second).UnixNano()
	exec(`INSERT INTO feature_windows(event_id,sensor_id,window_start_ns,window_end_ns,payload,received_at)
		SELECT id, 'online', $1::bigint + offset_s * 1000000000::bigint,
		       $1::bigint + (offset_s+5) * 1000000000::bigint,
		       jsonb_build_object('feature_set_version',feature_set,'entity_type','host','entity_id','192.0.2.10','capture_epoch','pilot-test'),
		       to_timestamp($1::bigint / 1e9 + offset_s + 6)
		FROM (VALUES ('before',0,'traffic-v3'), ('normal',5,'traffic-v3'), ('alert-a',5,'traffic-v3'),
		       ('alert-b',10,'traffic-v3'), ('poor',15,'traffic-v3'), ('other-model',20,'traffic-v3'),
		       ('gate',25,'traffic-v3'), ('legacy',30,'traffic-v1'), ('after-end',604800,'traffic-v3'),
		       ('false-a',35,'traffic-v3'), ('false-b',40,'traffic-v3'), ('background',45,'traffic-v3')
		) f(id,offset_s,feature_set)`, base)
	exec(`INSERT INTO inference_jobs(event_id,model_id,policy_version)
		SELECT event_id, CASE WHEN event_id='other-model' THEN 'different' ELSE 'selected' END, 'v1'
		FROM feature_windows`)
	exec(`INSERT INTO catalog_incidents(stream_key,sensor_id,entity_id,attack_type,source,detector_version,first_ns,last_ns)
		VALUES ('stream','online','192.0.2.10','tcp_port_scan','rules','rules-test',$1,$2)`,
		base+5e9, base+15e9)
	exec(`INSERT INTO catalog_incidents(stream_key,sensor_id,entity_id,attack_type,source,detector_version,first_ns,last_ns)
		VALUES ('background','online','192.0.2.10','unknown','ml','ml-test',$1,$2)`, base+35e9, base+45e9)
	exec(`INSERT INTO catalog_decisions(event_id,model_id,policy_version,status,payload,incident_id,decided_at)
		SELECT j.event_id, j.model_id, j.policy_version,
		       CASE WHEN j.event_id IN ('alert-a','alert-b','false-a','false-b') THEN 'incident' WHEN j.event_id='poor' THEN 'insufficient_data'
		            WHEN j.event_id='gate' THEN 'no_match' ELSE 'normal' END,
		       '{}', CASE WHEN j.event_id IN ('alert-a','alert-b') THEN (SELECT id FROM catalog_incidents WHERE stream_key='stream')
		                  WHEN j.event_id IN ('false-a','false-b') THEN (SELECT id FROM catalog_incidents WHERE stream_key='background') END,
		       to_timestamp(w.window_end_ns / 1e9 + 2)
		FROM inference_jobs j JOIN feature_windows w USING(event_id)`)

	exec(`INSERT INTO sensor_resource_samples(sensor_id, sampled_at, cpu_pct, rss_bytes) VALUES
		('online',$1,99,10000), ('online',$2,2,100), ('online',$3,4,200), ('online',$4,99,10000)`,
		start.Add(-time.Minute), start.Add(time.Minute), start.Add(2*time.Minute), end)
	raw, err := db.PilotReport(ctx, "campus")
	if err != nil {
		t.Fatal(err)
	}
	type totals struct {
		SensorID     string         `json:"sensor_id"`
		Expected     int            `json:"expected_slots"`
		Received     int            `json:"received_slots"`
		Usable       int            `json:"usable_slots"`
		Windows      int            `json:"received_windows"`
		Insufficient int            `json:"insufficient_windows"`
		Unresolved   int            `json:"unresolved_windows"`
		Alerts       int            `json:"alert_windows"`
		Incidents    int            `json:"incidents"`
		ByType       map[string]int `json:"by_type"`
		BySource     map[string]int `json:"by_source"`
		P95          *float64       `json:"p95_delay_s"`
		Samples      int            `json:"resource_samples"`
		CPU          *float64       `json:"mean_cpu_pct"`
		RSS          *int64         `json:"peak_rss_bytes"`
	}
	var report struct {
		Complete bool      `json:"complete"`
		AsOf     time.Time `json:"as_of"`
		End      time.Time `json:"ends_at"`
		Sensors  []totals  `json:"sensors"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Complete || !report.End.Equal(end) || !report.AsOf.Equal(end) || len(report.Sensors) != 3 {
		t.Fatalf("incorrect report bounds or roster: %s", raw)
	}
	byID := map[string]totals{}
	for _, row := range report.Sensors {
		byID[row.SensorID] = row
	}
	online := byID["online"]
	if online.Expected != 120959 || online.Received != 8 || online.Usable != 5 || online.Windows != 9 ||
		online.Alerts != 4 || online.Incidents != 2 || online.Insufficient != 1 || online.Unresolved != 2 ||
		online.ByType["tcp_port_scan"] != 1 || online.BySource["rules"] != 1 || online.P95 == nil || *online.P95 != 2 {
		t.Errorf("online sensor totals: %+v", online)
	}
	if online.Samples != 2 || online.CPU == nil || *online.CPU != 3 || online.RSS == nil || *online.RSS != 200 {
		t.Errorf("incorrect in-period CPU and memory usage: %+v", online)
	}
	for id, expected := range map[string]int{"silent": 120959, "late": 3} {
		s := byID[id]
		if s.Expected != expected || s.Received != 0 || s.Usable != 0 || s.Incidents != 0 || s.P95 != nil ||
			s.Samples != 0 || s.CPU != nil || s.RSS != nil {
			t.Errorf("%s sensor totals: %+v", id, s)
		}
	}
	t.Run("compare against independently labelled intervals", func(t *testing.T) {
		testPilotReferences(t, db, start.Truncate(5*time.Second))
	})

}

func testPilotReferences(t *testing.T, db *store.Store, base time.Time) {
	t.Helper()
	ctx := context.Background()
	label := func(id, kind string, left, right int) store.PilotLabel {
		return store.PilotLabel{ID: id, SensorID: "online", Type: kind,
			Start: base.Add(time.Duration(left) * time.Second), End: base.Add(time.Duration(right) * time.Second)}
	}
	add := func(l store.PilotLabel, want error) {
		t.Helper()
		if err := db.AddPilotLabel(ctx, "campus", "operator-a", l); !errors.Is(err, want) {
			t.Errorf("label %+v: got %v, want %v", l, err, want)
		}
	}
	type summary struct {
		Episodes  int                                               `json:"attack_episodes"`
		Detected  int                                               `json:"detected_episodes"`
		Correct   int                                               `json:"correctly_typed_episodes"`
		Slots     int                                               `json:"normal_slots"`
		False     int                                               `json:"false_incidents"`
		FalseRate *float64                                          `json:"false_per_100h"`
		ByType    map[string]struct{ Total, Detected, Correct int } `json:"by_type"`
	}
	reference := func() *summary {
		t.Helper()
		raw, err := db.PilotReport(ctx, "campus")
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Sensors []struct {
				ID        string   `json:"sensor_id"`
				Reference *summary `json:"reference"`
			} `json:"sensors"`
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Fatal(err)
		}
		for _, sensor := range report.Sensors {
			if sensor.ID == "online" {
				return sensor.Reference
			}
		}
		t.Fatal("missing registered sensor")
		return nil
	}
	if got := reference(); got != nil {
		t.Fatalf("received evidence before labels were supplied: %+v", got)
	}
	add(label("outside", "normal", 0, 5), store.ErrPilotLabel)
	add(label("outside", "normal", 604800, 604805), store.ErrPilotLabel)
	add(label("inverted", "normal", 10, 5), store.ErrPilotLabel)
	add(label("right", "tcp_port_scan", 5, 10), nil)
	add(label("right", "tcp_port_scan", 5, 10), nil)
	add(label("right", "udp_flood", 5, 10), store.ErrConflict)
	add(label("overlaps", "normal", 9, 11), store.ErrConflict)
	add(label("wrong", "icmp_flood", 10, 15), nil)
	add(label("missed", "udp_flood", 15, 20), nil)
	got := reference()
	if got == nil || got.Episodes != 3 || got.Detected != 2 || got.Correct != 1 || got.FalseRate != nil ||
		got.ByType["tcp_port_scan"].Correct != 1 || got.ByType["icmp_flood"].Detected != 1 ||
		got.ByType["icmp_flood"].Correct != 0 || got.ByType["udp_flood"].Total != 1 || got.ByType["udp_flood"].Detected != 0 {
		t.Fatalf("incorrect episode counts before any measured normal time: %+v", got)
	}
	add(label("benign", "normal", 35, 50), nil)
	got = reference()
	if got == nil || got.Slots != 3 || got.False != 1 || got.FalseRate == nil || *got.FalseRate != 24000 {
		t.Fatalf("merged two-window false incident / 15 seconds of usable normal traffic: %+v", got)
	}
}

func TestPilotAnalyzerSamplesOnlyDuringItsWeek(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	for _, name := range []string{"future", "expired", "running"} {
		if _, err := db.StartPilot(ctx, name, "model", "v1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE pilots SET started_at = started_at +
		CASE name WHEN 'future' THEN interval '1 day' ELSE interval '-8 days' END WHERE name <> 'running'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := db.SamplePilotHealth(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var total, buckets, active int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*),count(DISTINCT minute_utc),
		count(*) FILTER (WHERE pilot_name='running' AND database_bytes>0 AND queued_jobs=0)
		FROM pilot_analyzer_samples`).Scan(&total, &buckets, &active); err != nil || total == 0 || total != buckets || active != total {
		t.Fatalf("unexpected sampled minutes: total=%d buckets=%d active=%d: %v", total, buckets, active, err)
	}
	raw, err := db.PilotReport(ctx, "running")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Analyzer struct {
			Samples   int    `json:"samples"`
			PeakQueue *int   `json:"peak_queue"`
			Growth    *int64 `json:"database_growth_bytes"`
		} `json:"analyzer"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Analyzer.Samples != total || report.Analyzer.PeakQueue == nil || *report.Analyzer.PeakQueue != 0 ||
		(total == 1 && report.Analyzer.Growth != nil) {
		t.Fatalf("invalid analyzer resource summary: %s", raw)
	}
}

func TestPilotRevocationBounds(t *testing.T) {
	db, _ := database(t)
	ctx := context.Background()
	start := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	stop := start.Add(62 * time.Second)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO pilots VALUES ('trial',$1,'model','policy')`, start)
	exec(`INSERT INTO registered_sensors(id,token_hash,registered_at)
	      VALUES ('retired',decode(repeat('01',32),'hex'),$1), ('during',decode(repeat('02',32),'hex'),$1)`,
		start.Add(-24*time.Hour))
	for _, id := range []string{"retired", "during"} {
		if err := db.SetSensorState(ctx, id, "revoke"); err != nil {
			t.Fatal(err)
		}
		var stamped time.Time
		if err := db.Pool.QueryRow(ctx, "SELECT revoked_at FROM registered_sensors WHERE id=$1", id).Scan(&stamped); err != nil {
			t.Fatal(err)
		}
	}
	exec(`UPDATE registered_sensors SET revoked_at=$1 WHERE id='retired'`, start.Add(-time.Hour))
	exec(`UPDATE registered_sensors SET revoked_at=$1 WHERE id='during'`, stop)
	if err := db.SetSensorState(ctx, "during", "revoke"); err != nil {
		t.Fatal(err)
	}

	exec(`INSERT INTO feature_windows(event_id,sensor_id,window_start_ns,window_end_ns,payload)
	      SELECT stamp::text, 'during', stamp, stamp+5000000000,
	             '{"feature_set_version":"traffic-v3","entity_type":"host"}'::jsonb
	      FROM unnest($1::bigint[]) stamp`,
		[]int64{start.Add(55 * time.Second).UnixNano(), start.Add(60 * time.Second).UnixNano()})
	exec(`INSERT INTO sensor_resource_samples VALUES
	      ('during',$1,1,1024), ('during',$2,2,4096)`, start.Add(30*time.Second), stop.Add(time.Second))

	label := store.PilotLabel{SensorID: "during", ID: "known", Start: start, End: stop, Type: "normal"}
	if err := db.AddPilotLabel(ctx, "trial", "test", label); err != nil {
		t.Fatal(err)
	}
	label.ID, label.Start, label.End = "outside", stop, stop.Add(time.Second)
	if err := db.AddPilotLabel(ctx, "trial", "test", label); !errors.Is(err, store.ErrPilotLabel) {
		t.Fatalf("accepted label beyond revocation: %v", err)
	}

	raw, err := db.PilotReport(ctx, "trial")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Sensors []struct {
			ID       string `json:"sensor_id"`
			Expected int    `json:"expected_slots"`
			Windows  int    `json:"received_windows"`
			Samples  int    `json:"resource_samples"`
			PeakRSS  int64  `json:"peak_rss_bytes"`
		} `json:"sensors"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Sensors) != 1 {
		t.Fatalf("unexpected pilot cohort: %s", raw)
	}
	s := report.Sensors[0]
	if s.ID != "during" || s.Expected != 12 || s.Windows != 1 || s.Samples != 1 || s.PeakRSS != 1024 {
		t.Fatalf("incorrect revocation boundary: %s", raw)
	}
}
