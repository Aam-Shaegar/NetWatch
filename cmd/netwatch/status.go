package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type queueStatus struct {
	Queued    int64    `json:"queued"`
	Retrying  int64    `json:"retrying"`
	Failed    int64    `json:"failed,omitempty"`
	OldestAge *float64 `json:"oldest_age_s"`
}

type pipelineStatus struct {
	ObservedAt time.Time `json:"observed_at"`
	Target     struct {
		Model  string `json:"model_id"`
		Policy string `json:"policy_version"`
	} `json:"target"`
	Capture *struct {
		Sensor     string    `json:"sensor_id"`
		FeatureSet string    `json:"feature_set_version"`
		ReceivedAt time.Time `json:"received_at"`
		ReceiptAge float64   `json:"receipt_age_s"`
		EventAge   float64   `json:"event_age_s"`
		Quality    struct {
			Coverage  string `json:"coverage"`
			Dropped   *int64 `json:"capture_dropped"`
			Late      int64  `json:"late_packets"`
			Evictions int64  `json:"state_evictions"`
		} `json:"quality"`
	} `json:"capture"`
	Prediction *struct {
		Status      string    `json:"status"`
		Unavailable *string   `json:"unavailable_reason"`
		ProcessedAt time.Time `json:"processed_at"`
		Age         float64   `json:"age_s"`
	} `json:"prediction"`
	Usable *struct {
		ProcessedAt     time.Time `json:"processed_at"`
		EventAge        float64   `json:"event_age_s"`
		ProcessingDelay float64   `json:"processing_delay_s"`
	} `json:"usable_prediction"`
	Inference        queueStatus `json:"inference"`
	Assessment       queueStatus `json:"assessment"`
	Projection       int64       `json:"projection_pending"`
	ProjectionOldest *float64    `json:"projection_oldest_age_s"`
	Gaps             int64       `json:"projection_gaps"`
}

func (c *operatorClient) status(ctx context.Context) (pipelineStatus, error) {
	var result pipelineStatus
	err := c.get(ctx, "/v1/pipeline/status", nil, &result)
	if err == nil && (result.ObservedAt.IsZero() || result.Target.Model == "" || result.Target.Policy == "") {
		err = errors.New("server does not provide the required pipeline status version")
	}
	return result, err
}

func age(seconds *float64) string {
	if seconds == nil {
		return "unknown"
	}
	return fmt.Sprintf("%.1fs", *seconds)
}

func (s pipelineStatus) print(out io.Writer) error {
	var text strings.Builder
	fmt.Fprintf(&text, "Model %s, policy %s\n", s.Target.Model, s.Target.Policy)
	if c := s.Capture; c == nil {
		fmt.Fprintln(&text, "Capture: no windows received")
	} else {
		fmt.Fprintf(&text, "Capture: %q %s, event %.1fs old, received %.1fs ago, %s, drops %s, late %d, evictions %d\n",
			c.Sensor, c.FeatureSet, c.EventAge, c.ReceiptAge, c.Quality.Coverage, packetCount(c.Quality.Dropped), c.Quality.Late, c.Quality.Evictions)
	}
	if s.Prediction == nil {
		fmt.Fprintln(&text, "Latest prediction: none for active model and policy")
	} else {
		fmt.Fprintf(&text, "Latest prediction: %s %.1fs ago", s.Prediction.Status, s.Prediction.Age)
		if s.Prediction.Unavailable != nil {
			fmt.Fprintf(&text, " (%s)", *s.Prediction.Unavailable)
		}
		fmt.Fprintln(&text)
	}
	if s.Usable != nil {
		fmt.Fprintf(&text, "Latest usable prediction: event %.1fs old, delivery and inference delay %.1fs\n", s.Usable.EventAge, s.Usable.ProcessingDelay)
	}
	fmt.Fprintf(&text, "Inference queue: %d pending, %d retrying, oldest %s\n", s.Inference.Queued, s.Inference.Retrying, age(s.Inference.OldestAge))
	fmt.Fprintf(&text, "Incident projection: %d pending, oldest %s, %d historical gaps\n", s.Projection, age(s.ProjectionOldest), s.Gaps)
	fmt.Fprintf(&text, "Assessment queue: %d pending, %d retrying, %d failed, oldest %s\n", s.Assessment.Queued, s.Assessment.Retrying, s.Assessment.Failed, age(s.Assessment.OldestAge))
	_, err := io.WriteString(out, text.String())
	return err
}

func packetCount(n *int64) string {
	if n == nil {
		return "unknown"
	}
	return strconv.FormatInt(*n, 10)
}

func (s pipelineStatus) issues(maxAge time.Duration) []string {
	issues := []string{}
	if c := s.Capture; c == nil {
		issues = append(issues, "no_capture_windows")
	} else {
		if c.EventAge > maxAge.Seconds() || c.ReceiptAge > maxAge.Seconds() {
			issues = append(issues, "capture_stale")
		}
		if c.EventAge < -5 {
			issues = append(issues, "capture_clock_ahead")
		}
		if c.Quality.Coverage != "complete" || c.Quality.Dropped == nil || *c.Quality.Dropped != 0 || c.Quality.Late != 0 || c.Quality.Evictions != 0 {
			issues = append(issues, "capture_quality_degraded")
		}
	}
	if s.Prediction == nil || (s.Prediction.Status != "normal" && s.Prediction.Status != "anomalous") {
		issues = append(issues, "latest_prediction_unavailable")
	}
	if s.Usable == nil || s.Usable.EventAge > maxAge.Seconds() || s.Usable.EventAge < -5 {
		issues = append(issues, "no_recent_usable_prediction")
	}
	if s.Inference.OldestAge != nil && *s.Inference.OldestAge > maxAge.Seconds() {
		issues = append(issues, "inference_backlog")
	}
	if s.ProjectionOldest != nil && *s.ProjectionOldest > maxAge.Seconds() {
		issues = append(issues, "projection_backlog")
	}
	return issues
}

func (c *operatorClient) doctor(ctx context.Context, maxAge time.Duration, machine bool, out io.Writer) (int, error) {
	result := struct {
		Ready  bool            `json:"ready"`
		Issues []string        `json:"issues"`
		Status *pipelineStatus `json:"pipeline"`
	}{Issues: []string{}}
	var health struct{ Status string }
	if err := c.get(ctx, "/health/ready", nil, &health); err != nil || health.Status != "ready" {
		result.Issues = append(result.Issues, "ingestion_not_ready")
	}
	status, err := c.status(ctx)
	if err != nil {
		result.Issues = append(result.Issues, "pipeline_status_unavailable")
	} else {
		result.Status = &status
		result.Issues = append(result.Issues, status.issues(maxAge)...)
	}
	result.Ready = len(result.Issues) == 0
	if machine {
		if err := json.NewEncoder(out).Encode(result); err != nil {
			return 1, err
		}
	} else if result.Ready {
		fmt.Fprintln(out, "Live analysis is ready")
	} else {
		fmt.Fprintln(out, "Live analysis is not ready:", strings.Join(result.Issues, ", "))
		if err != nil {
			fmt.Fprintln(out, err)
		}
	}
	if !result.Ready {
		return 2, nil
	}
	return 0, nil
}

func (c *operatorClient) incidents(ctx context.Context, query url.Values, machine bool, out io.Writer) error {
	var result json.RawMessage
	if err := c.get(ctx, "/v1/incidents", query, &result); err != nil {
		return err
	}
	if machine {
		return json.NewEncoder(out).Encode(result)
	}
	var page struct {
		Incidents []struct {
			ID, Entity, Model, Policy string
			First                     string `json:"first_ns"`
			Detected                  string `json:"detected_ns"`
			EstimatedEnd              string `json:"estimated_end_ns"`
			Interrupted               string `json:"interrupted_ns"`
		}
		Next string
	}
	if err := json.Unmarshal(result, &page); err != nil {
		return err
	}
	var text strings.Builder
	if len(page.Incidents) == 0 {
		fmt.Fprintln(&text, "No incidents in the requested range")
	}
	for _, item := range page.Incidents {
		state := "open"
		if item.EstimatedEnd != "" {
			state = "ended " + eventTime(item.EstimatedEnd)
		}
		if item.Interrupted != "" {
			state = "interrupted " + eventTime(item.Interrupted) + " (end unknown)"
		}
		fmt.Fprintf(&text, "%s %q %s (%s/%s), start %s, detected %s\n", item.ID, item.Entity, state,
			item.Model, item.Policy, eventTime(item.First), eventTime(item.Detected))
	}
	if page.Next != "" {
		fmt.Fprintf(&text, "Next page: --before %s\n", page.Next)
	}
	_, err := io.WriteString(out, text.String())
	return err
}

func eventTime(ns string) string {
	value, err := strconv.ParseInt(ns, 10, 64)
	if err != nil {
		return "unknown"
	}
	return time.Unix(0, value).UTC().Format(time.RFC3339Nano)
}
