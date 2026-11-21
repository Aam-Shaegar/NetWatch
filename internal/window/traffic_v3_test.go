package window

import (
	"testing"

	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/decode"
)

func TestTrafficV3DirectionsAndVersionedIdentity(t *testing.T) {
	base := config()
	current := base
	current.FeatureSet = contract.TrafficV3
	records := fixture(t, "syn-retry.pcap")
	for i := range records {
		records[i].Src, records[i].Dst = records[i].Dst, records[i].Src
	}
	another := records[0]
	another.DstPort = new(uint16)
	*another.DstPort = 80
	records = append(records, another)
	records = append(records,
		decode.Meta{Src: "198.51.100.20", Dst: base.Host.String(), Timestamp: records[0].Timestamp,
			Protocol: "UDP", Status: "decoded", IPLength: 50},
		decode.Meta{Src: "198.51.100.20", Dst: base.Host.String(), Timestamp: records[0].Timestamp,
			Protocol: "ICMP", Status: "decoded", IPLength: 32},
		decode.Meta{Src: base.Host.String(), Dst: "198.51.100.20", Timestamp: records[0].Timestamp,
			Protocol: "UDP", Status: "decoded", IPLength: 60},
	)
	result := run(t, current, records)[0]
	engine, err := New(current)
	if err != nil {
		t.Fatal(err)
	}
	window, err := engine.Export(result, "sensor", "run")
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]float64{
		"in_tcp_distinct_ports_per_source_max": 2,
		"in_udp_packets":                       1,
		"in_udp_ip_bytes":                      50,
		"in_icmp_packets":                      1,
		"in_icmp_ip_bytes":                     32,
	} {
		if got := window.Features[field]; got == nil || *got != want {
			t.Errorf("%s = %v, want %v", field, got, want)
		}
	}
	oldEngine, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := oldEngine.Export(result, "sensor", "run")
	if err != nil || legacy.EventID == window.EventID {
		t.Fatalf("legacy and v3 event IDs must differ: %v", err)
	}
	current.MaxUnique = 1
	capped := run(t, current, records)[0]
	window, err = engine.Export(capped, "sensor", "run")
	if err != nil || window.Quality.Coverage != "gap" || window.Features["in_tcp_distinct_ports_per_source_max"] != nil {
		t.Fatalf("overflowed fanout must be null in a gap: %+v %v", window.Quality, err)
	}
}
