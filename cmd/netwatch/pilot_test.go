package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPilotCommands(t *testing.T) {
	const token = "test-operator-token-with-at-least-32-bytes"
	start := `{"name":"campus","started_at":"2026-11-10T08:00:00Z","ends_at":"2026-11-17T08:00:00Z","model_id":"detector","policy_version":"v1"}`
	report := strings.TrimSuffix(start, "}") + `,"as_of":"2026-11-17T08:00:00Z","complete":true,"analyzer":{"samples":2,"peak_queue":8,"database_growth_bytes":-1048576},
		"sensors":[{"sensor_id":"host1","usable_slots":900,"expected_slots":1200,"coverage_pct":75,"p95_delay_s":1.524,"incidents":2,"by_type":{"unknown":2},"by_source":{"ml":2},"resource_samples":12,"mean_cpu_pct":3.2,"peak_rss_bytes":1048576,"reference":{"attack_episodes":2,"detected_episodes":1,"correctly_typed_episodes":1,"normal_slots":100,"false_incidents":1,"false_per_100h":720,"by_type":{"udp_flood":{"total":2,"detected":1,"correct":1}}}},
		{"sensor_id":"offline","expected_slots":120960,"received_slots":0,"coverage_pct":0,"p95_delay_s":null}]}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/pilots/campus/start":
			io.WriteString(w, start)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/pilots/campus/report":
			io.WriteString(w, report)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/pilots/campus/labels":
			var label pilotLabel
			if err := json.NewDecoder(r.Body).Decode(&label); err != nil || label.From.Format(time.RFC3339) != "2026-11-10T08:00:00Z" ||
				label.Sensor != "host1" || label.ID != "event1" || label.Type != "normal" {
				http.Error(w, "bad label", http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(label)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	cert := server.Certificate()
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETWATCH_URL", server.URL)
	t.Setenv("NETWATCH_OPERATOR_TOKEN_FILE", tokenFile)
	t.Setenv("NETWATCH_CA_FILE", ca)
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"label", "campus", "--sensor", "host1", "--id", "event1", "--from", "2026-11-10T11:00:00+03:00", "--until", "2026-11-10T11:05:00+03:00", "--type", "normal", "--json"}, []string{`"type":"normal"`, `"start":"2026-11-10T08:00:00Z"`}},
		{[]string{"start", "campus"}, []string{"netwatch pilot report campus"}},
		{[]string{"report", "campus"}, []string{"период завершён", "75.00%", "1.524 с", "unknown=2", "1.0 МиБ", "максимум очереди 8", "-1.00 МиБ", "udp_flood: обнаружено 1/2", "нет разметки", "Сенсор offline", "p95): нет данных"}},
		{[]string{"report", "campus", "--json"}, []string{`"complete":true`, `"sensor_id":"offline"`}},
	} {
		var stdout, stderr bytes.Buffer
		code, err := run(context.Background(), append([]string{"pilot"}, tc.args...), nil, &stdout, &stderr)
		if err != nil || code != 0 {
			t.Fatalf("%s: code %d, err %v, stderr %s", tc.args, code, err, &stderr)
		}
		for _, expected := range tc.want {
			if !strings.Contains(stdout.String(), expected) {
				t.Fatalf("%s: missing %q in %s", tc.args, expected, &stdout)
			}
		}
		if tc.args[len(tc.args)-1] == "--json" && !json.Valid(stdout.Bytes()) {
			t.Fatalf("invalid machine-readable report: %s", &stdout)
		}
	}
}

func TestPilotRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{{"pilot", "start"}, {"pilot", "remove", "campus"}, {"pilot", "report", "../campus"}, {"pilot", "label", "campus", "--sensor", "host1"}} {
		code, err := run(context.Background(), args, nil, io.Discard, io.Discard)
		if code != 1 || err == nil {
			t.Fatalf("%q accepted", args)
		}
	}
}
