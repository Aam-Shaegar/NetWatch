package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"netwatch.local/netwatch/internal/telemetry"
)

type slot struct {
	ID   string `json:"id"`
	Time int64  `json:"time_s"`
}

type result struct {
	ID        string  `json:"id"`
	Entity    string  `json:"entity"`
	Cohort    string  `json:"cohort"`
	Time      float64 `json:"time_s"`
	Available bool    `json:"available"`
}

type probeLog struct {
	Entity   string   `json:"entity"`
	Cohort   string   `json:"cohort"`
	Start    int64    `json:"start_s"`
	Valid    int64    `json:"policy_valid_until_s"`
	Schedule []slot   `json:"schedule"`
	Results  []result `json:"results"`
}

func main() {
	log := telemetry.NewLogger("probe")
	var target string
	record := probeLog{Results: []result{}}
	flag.StringVar(&target, "url", "", "configured HTTP(S) health endpoint")
	flag.StringVar(&record.Entity, "entity", "", "observed service")
	flag.StringVar(&record.Cohort, "cohort", "", "observation scope shared with other observers")
	flag.Int64Var(&record.Start, "start", 0, "Unix timestamp of the next observation minute")
	flag.Int64Var(&record.Valid, "policy-valid-until", 0, "Unix expiry timestamp of the probe configuration")
	flag.Parse()

	now := time.Now()
	if err := validate(target, record, now); err != nil {
		log.Error("probe_failed", "error", err.Error())
		os.Exit(1)
	}

	end := time.Unix(record.Start+60, 0)
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, second := range []int64{5, 20, 35, 50} {
		sample := slot{ID: fmt.Sprint(second), Time: record.Start + second}
		record.Schedule = append(record.Schedule, sample)
		at := time.Unix(sample.Time, 0)
		time.Sleep(time.Until(at))
		if time.Since(at) > time.Second {
			continue
		}
		available := checkHealth(client, target, end)
		finished := time.Now()
		if finished.Before(end) {
			record.Results = append(record.Results, result{
				ID: sample.ID, Entity: record.Entity, Cohort: record.Cohort,
				Time: float64(finished.UnixNano()) / float64(time.Second), Available: available,
			})
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(record); err != nil {
		log.Error("probe_failed", "error", err.Error())
		os.Exit(1)
	}
}

func validate(target string, record probeLog, now time.Time) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("url must be an HTTP(S) health endpoint")
	}
	if record.Entity == "" || record.Cohort == "" || record.Start < now.Unix() || record.Start > now.Unix()+60 ||
		record.Valid < record.Start+60 {
		return fmt.Errorf("entity, cohort, a start within the next 60 seconds and policy valid through the interval are required")
	}
	return nil
}

func checkHealth(client *http.Client, target string, end time.Time) bool {
	ctx, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
