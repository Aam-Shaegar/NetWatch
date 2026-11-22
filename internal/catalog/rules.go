package catalog

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"netwatch.local/netwatch/internal/contract"
)

const (
	FeatureSet   = "traffic-v3"
	TCPPortScan  = "tcp_port_scan"
	UDPFlood     = "udp_flood"
	ICMPFlood    = "icmp_flood"
	Unknown      = "unknown"
	Incident     = "incident"
	NoMatch      = "no_match"
	Normal       = "normal"
	Insufficient = "insufficient_data"
	HistoryLimit = 60
	HistoryAge   = 5 * time.Minute
)

const TemporalModelID = "v1-temporal-a721ab9def3befdc68c8d3c5"

type Decision struct {
	EventID         string  `json:"event_id"`
	Status          string  `json:"status"`
	AttackType      *string `json:"attack_type"`
	Source          string  `json:"source,omitempty"`
	DetectorVersion string  `json:"detector_version,omitempty"`
	Reason          string  `json:"reason,omitempty"`
}

type Rules struct {
	disabled map[string]bool
}

func KnownType(name string) bool {
	return name == TCPPortScan || name == UDPFlood || name == ICMPFlood
}

func NewRules(disabled string) (Rules, error) {
	r := Rules{disabled: map[string]bool{}}
	if strings.TrimSpace(disabled) == "" {
		return r, nil
	}
	for name := range strings.SplitSeq(disabled, ",") {
		name = strings.TrimSpace(name)
		if !KnownType(name) {
			return Rules{}, fmt.Errorf("unknown disabled rule %q", name)
		}
		r.disabled[name] = true
	}
	return r, nil
}

type RuleSetting struct {
	Version int  `json:"version"`
	Enabled bool `json:"enabled"`
}

func (r Rules) Settings() map[string]RuleSetting {
	settings := make(map[string]RuleSetting, 3)
	for _, name := range []string{TCPPortScan, UDPFlood, ICMPFlood} {
		settings[name] = RuleSetting{Version: 1, Enabled: !r.disabled[name]}
	}
	return settings
}

func Eligible(w contract.Window) bool {
	return w.FeatureSetVersion == FeatureSet && w.EntityType == "host" &&
		w.Quality.Coverage == "complete" && w.Quality.CaptureDropped != nil &&
		*w.Quality.CaptureDropped == 0 && w.Quality.LatePackets == 0 && w.Quality.StateEvictions == 0
}

func dimensions(w contract.Window) (start, end int64, seconds float64) {
	start, _ = strconv.ParseInt(w.WindowStartNS, 10, 64)
	end, _ = strconv.ParseInt(w.WindowEndNS, 10, 64)
	return start, end, float64(end-start) / float64(time.Second)
}

// Evaluate looks only at older, eligible observations of the same protected host.
// Missing baseline prevents a flood rule match while the observation remains eligible for ML.
func (r Rules) Evaluate(w contract.Window, history []contract.Window) Decision {
	decision := Decision{EventID: w.EventID, Status: NoMatch}
	start, _, seconds := dimensions(w)
	fanout := w.Features["in_tcp_distinct_ports_per_source_max"]
	if !Eligible(w) || seconds <= 0 || fanout == nil {
		decision.Status = Insufficient
		decision.Reason = "incomplete_measurement"
		return decision
	}
	total := w.Features["in_packets"]
	udp, icmp := w.Features["in_udp_packets"], w.Features["in_icmp_packets"]
	if total == nil || udp == nil || icmp == nil {
		decision.Status = Insufficient
		decision.Reason = "incomplete_measurement"
		return decision
	}
	// A protocol-specific flood and an unrelated port scan can coincide. Deterministic
	// precedence keeps v1 at one result per window, with flood requiring dominant traffic.
	for _, rule := range []struct {
		attack, feature string
		count           float64
	}{
		{UDPFlood, "in_udp_packets", *udp},
		{ICMPFlood, "in_icmp_packets", *icmp},
	} {
		if !r.disabled[rule.attack] && *total > 0 && rule.count / *total >= 0.7 &&
			rule.count/seconds >= 100 && aboveBaseline(w, start, rule.feature, rule.count/seconds, history) {
			return ruleDecision(w.EventID, rule.attack, "protocol_rate_above_host_baseline")
		}
	}
	if !r.disabled[TCPPortScan] && *fanout >= 16 {
		return ruleDecision(w.EventID, TCPPortScan, "tcp_destination_port_fanout")
	}
	return decision
}

func ruleDecision(eventID, attack, reason string) Decision {
	return Decision{EventID: eventID, Status: Incident, AttackType: &attack, Source: "rules", DetectorVersion: attack + "/1", Reason: reason}
}

func aboveBaseline(w contract.Window, start int64, feature string, rate float64, history []contract.Window) bool {
	rates := make([]float64, 0, len(history))
	for _, prior := range history {
		_, end, seconds := dimensions(prior)
		if end > start || end <= start-int64(HistoryAge) || seconds <= 0 || !Eligible(prior) ||
			prior.SensorID != w.SensorID || prior.CaptureEpoch != w.CaptureEpoch || prior.EntityID != w.EntityID {
			continue
		}
		if count := prior.Features[feature]; count != nil {
			rates = append(rates, *count/seconds)
		}
	}
	if len(rates) < 5 {
		return false
	}
	slices.Sort(rates)
	median := rates[len(rates)/2]
	for i, value := range rates {
		rates[i] = max(value-median, median-value)
	}
	slices.Sort(rates)
	return rate > median+max(median, 6*rates[len(rates)/2])
}
