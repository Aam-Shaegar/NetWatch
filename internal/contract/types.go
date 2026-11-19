package contract

const (
	TrafficV1 = "traffic-v1"
	TrafficV2 = "traffic-v2"
)

func IsTrafficFeatureSet(version string) bool {
	return version == TrafficV1 || version == TrafficV2
}

// Window mirrors the versioned wire contract. Validate raw JSON before decoding.
// Values that were not observable must remain null (nil), not zero.
type Window struct {
	SchemaVersion     int                 `json:"schema_version"`
	FeatureSetVersion string              `json:"feature_set_version"`
	EventID           string              `json:"event_id"`
	SensorID          string              `json:"sensor_id"`
	CaptureEpoch      string              `json:"capture_epoch"`
	EntityType        string              `json:"entity_type"`
	EntityID          string              `json:"entity_id"`
	WindowStartNS     string              `json:"window_start_ns"`
	WindowEndNS       string              `json:"window_end_ns"`
	Features          map[string]*float64 `json:"features"`
	Quality           Quality             `json:"quality"`
}
type Quality struct {
	Coverage       string `json:"coverage"`
	CaptureDropped *int64 `json:"capture_dropped"`
	LatePackets    int64  `json:"late_packets"`
	StateEvictions int64  `json:"state_evictions"`
}
type Classification struct {
	Label       string   `json:"label"`
	Probability *float64 `json:"probability"`
	Version     string   `json:"version"`
}

type DecisionDiagnostics struct {
	ForestScore     float64  `json:"forest_score"`
	ForestThreshold float64  `json:"forest_threshold"`
	PatternLabel    string   `json:"pattern_label,omitempty"`
	PatternRatio    *float64 `json:"pattern_ratio,omitempty"`
}

type Prediction struct {
	Observational     bool                 `json:"observational,omitempty"`
	Diagnostics       *DecisionDiagnostics `json:"diagnostics,omitempty"`
	Reason            string               `json:"reason,omitempty"`
	UnavailableReason string               `json:"unavailable_reason,omitempty"`
	Classification    *Classification      `json:"classification,omitempty"`

	SchemaVersion     int      `json:"schema_version"`
	EventID           string   `json:"event_id"`
	ModelID           string   `json:"model_id"`
	FeatureSetVersion string   `json:"feature_set_version"`
	Status            string   `json:"status"`
	Score             *float64 `json:"score"`
	Threshold         *float64 `json:"threshold"`
}
