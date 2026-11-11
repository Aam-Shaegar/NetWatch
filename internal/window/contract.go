package window

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"netwatch.local/netwatch/internal/contract"
)

// Export produces the shared traffic-v1 contract with explicit unavailable values.
func (e *Engine) Export(r Result, sensor, epoch string) (contract.Window, error) {
	kind, entity := "host", e.config.Host.String()
	if e.config.Service.IsValid() {
		kind, entity = "destination_service", e.config.Protocol+"/"+e.config.Service.String()
	}
	identity, _ := json.Marshal([]string{sensor, epoch, kind, entity, strconv.FormatInt(r.Start, 10)})
	w := contract.Window{
		SchemaVersion: 1, FeatureSetVersion: "traffic-v1",
		EventID:  fmt.Sprintf("%x", sha256.Sum256(identity)),
		SensorID: sensor, CaptureEpoch: epoch, EntityType: kind, EntityID: entity,
		WindowStartNS: strconv.FormatInt(r.Start, 10), WindowEndNS: strconv.FormatInt(r.End, 10),
		Features: map[string]*float64{
			"syn_fraction": r.SYNFraction, "rst_fraction": r.RSTFraction,
			"mean_packet_size": r.MeanPacketSize, "std_packet_size": r.StdPacketSize,
			"mean_interarrival_seconds": r.MeanInterarrival, "std_interarrival_seconds": r.StdInterarrival,
		},
		Quality: contract.Quality{Coverage: r.Coverage},
	}
	for name, n := range map[string]uint64{
		"in_packets": r.InPackets, "out_packets": r.OutPackets,
		"in_ip_bytes": r.InBytes, "out_ip_bytes": r.OutBytes,
		"new_tcp_attempts": r.NewTCPAttempts, "established_tcp_attempts": r.EstablishedTCPAttempts,
		"completed_flow_count": r.CompletedFlows,
	} {
		if n > 1<<53 {
			return w, fmt.Errorf("%s exceeds exact JSON feature range", name)
		}
		v := float64(n)
		w.Features[name] = &v
	}
	for name, c := range map[string]Count{
		"unique_peers": r.Peers, "unique_destination_ports": r.DestinationPorts, "active_flows": r.ActiveFlows,
	} {
		w.Features[name] = nil
		if !c.Overflow {
			v := float64(c.Value)
			w.Features[name] = &v
		}
	}
	if r.LatePackets > math.MaxInt64 || r.StateEvictions > math.MaxInt64 {
		return w, fmt.Errorf("quality counter overflow")
	}
	w.Quality.LatePackets = int64(r.LatePackets)
	w.Quality.StateEvictions = int64(r.StateEvictions)
	data, err := json.Marshal(w)
	if err == nil {
		err = contract.Validate("window", data)
	}
	return w, err
}
