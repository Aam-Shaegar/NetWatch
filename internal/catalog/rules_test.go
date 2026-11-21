package catalog

import (
	"strconv"
	"testing"
	"time"

	"netwatch.local/netwatch/internal/contract"
)

func sample(at int64, tcpPorts, udp, icmp, total float64) contract.Window {
	noDrops := int64(0)
	return contract.Window{
		FeatureSetVersion: FeatureSet, EventID: "sample", SensorID: "sensor", CaptureEpoch: "epoch", EntityType: "host", EntityID: "192.0.2.1",
		WindowStartNS: strconv.FormatInt(at, 10), WindowEndNS: strconv.FormatInt(at+int64(5*time.Second), 10),
		Features: map[string]*float64{"in_packets": &total, "in_tcp_distinct_ports_per_source_max": &tcpPorts, "in_udp_packets": &udp, "in_icmp_packets": &icmp},
		Quality:  contract.Quality{Coverage: "complete", CaptureDropped: &noDrops},
	}
}

func TestPortScanRuleAndDisablement(t *testing.T) {
	r, _ := NewRules("")
	for _, tc := range []struct {
		ports  float64
		status string
	}{{15, NoMatch}, {16, Incident}} {
		w := sample(0, tc.ports, 0, 0, 16)
		d := r.Evaluate(w, nil)
		if d.Status != tc.status || (tc.status == Incident && (*d.AttackType != TCPPortScan || d.DetectorVersion != "tcp_port_scan/1")) {
			t.Fatalf("ports %v: %+v", tc.ports, d)
		}
	}
	disabled, err := NewRules(TCPPortScan)
	if err != nil || disabled.Evaluate(sample(0, 30, 0, 0, 50), nil).Status != NoMatch {
		t.Fatalf("disabled port scan matched: %v", err)
	}
}

func TestProtocolFloodRulesUseOwnPastHostAndProtocol(t *testing.T) {
	r, _ := NewRules("")
	var history []contract.Window
	for i := int64(0); i < 5; i++ {
		history = append(history, sample(i*int64(5*time.Second), 0, 25, 10, 100))
	}
	at := int64(25 * time.Second)
	cases := []struct {
		name, attack string
		window       contract.Window
	}{
		{"UDP", UDPFlood, sample(at, 0, 900, 0, 1000)},
		{"ICMP", ICMPFlood, sample(at, 0, 0, 900, 1000)},
		{"ordinary traffic", "", sample(at, 0, 0, 20, 100)},
		{"not dominant", "", sample(at, 0, 700, 0, 1500)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := r.Evaluate(tc.window, history)
			if tc.attack == "" {
				if d.Status != NoMatch {
					t.Fatalf("unexpected decision: %+v", d)
				}
			} else if d.Status != Incident || d.AttackType == nil || *d.AttackType != tc.attack {
				t.Fatalf("expected %s: %+v", tc.attack, d)
			}
		})
	}
	otherHost := cases[0].window
	otherHost.EntityID = "192.0.2.2"
	if d := r.Evaluate(otherHost, history); d.Status != NoMatch {
		t.Fatalf("mismatched history used: %+v", d)
	}
	unusable := cases[1].window
	unusable.Quality.CaptureDropped = nil
	if d := r.Evaluate(unusable, history); d.Status != Insufficient {
		t.Fatalf("unknown packet loss used: %+v", d)
	}
}
