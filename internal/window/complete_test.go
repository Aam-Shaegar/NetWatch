package window

import (
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"testing"

	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/decode"
)

func TestGoldenFeaturesAndCoverage(t *testing.T) {
	data, err := os.ReadFile("../../contracts/examples/window.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden contract.Window
	if err = json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	start, _ := strconv.ParseInt(golden.WindowStartNS, 10, 64)
	end, _ := strconv.ParseInt(golden.WindowEndNS, 10, 64)
	c := config()
	c.CoverageStart, c.CoverageEnd = &start, &end
	e, _ := New(c)
	for _, p := range fixture(t, "syn-retry.pcap") {
		if _, err = e.Push(p); err != nil {
			t.Fatal(err)
		}
	}
	w, err := e.Export(e.Finish()[0], "test", "fixture")
	if err != nil || !reflect.DeepEqual(w.Features, golden.Features) || !reflect.DeepEqual(w.Quality, golden.Quality) {
		t.Fatalf("golden mismatch: %+v %v", w, err)
	}
	if w2, _ := e.Export(Result{Start: start, End: end, Coverage: "partial"}, "test", "other"); w2.EventID == w.EventID {
		t.Fatal("epochs share event identity")
	}
}

func TestConnectionEventsAndPopulationStatistics(t *testing.T) {
	p := fixture(t, "flow-directions.pcap")[:2]
	base, _ := strconv.ParseInt(p[0].Timestamp, 10, 64)
	add := func(packet decode.Meta, second int64, flags uint8, seq, ack uint32) {
		packet.Timestamp = strconv.FormatInt(base+second*1e9, 10)
		packet.TCPFlags, packet.TCPSeq, packet.TCPAck = &flags, &seq, &ack
		p = append(p, packet)
	}
	add(p[0], 2, 16, 1, 20)
	add(p[0], 3, 16, 1, 20) // repeated ACK must not establish twice
	add(p[1], 4, 4, 20, 1)
	w := run(t, config(), p)[0]
	if w.EstablishedTCPAttempts != 1 || w.CompletedFlows != 1 || w.NewTCPAttempts != 1 {
		t.Fatalf("events: %+v", w)
	}
	if *w.SYNFraction != 0.4 || *w.RSTFraction != 0.2 || *w.MeanPacketSize != 40 || *w.StdPacketSize != 0 || *w.MeanInterarrival != 1 || *w.StdInterarrival != 0 {
		t.Fatalf("statistics: %+v", w)
	}
	var m moments
	for _, v := range []float64{10, 20, 30} {
		m.add(v)
	}
	mean, std := m.values()
	if *mean != 20 || math.Abs(*std-math.Sqrt(200.0/3)) > 1e-12 {
		t.Fatal("wrong population variance")
	}
}

func TestMultipleClientsAndNulls(t *testing.T) {
	p := fixture(t, "flow-directions.pcap")
	second := p[0]
	second.Src = "192.0.2.11"
	c := config()
	c.Host = netip.Addr{}
	c.Service = netip.MustParseAddrPort("198.51.100.20:443")
	c.Protocol = "TCP"
	w := run(t, c, []decode.Meta{p[0], second, p[1]})[0]
	if w.Peers.Value != 2 || w.ActiveFlows.Value != 2 || w.NewTCPAttempts != 2 || w.InPackets != 2 || w.OutPackets != 1 || w.InBytes != 80 {
		t.Fatalf("service aggregation: %+v", w)
	}
	e, _ := New(config())
	icmp := fixture(t, "mixed.pcap")[3]
	e.Push(icmp)
	result := e.Finish()[0]
	exported, err := e.Export(result, "test", "one")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"syn_fraction", "rst_fraction", "mean_interarrival_seconds", "std_interarrival_seconds"} {
		if exported.Features[name] != nil {
			t.Fatal("unavailable value must be null", name)
		}
	}
	c = config()
	c.MaxUnique = 1
	e, _ = New(c)
	e.Push(p[0])
	other := p[0]
	other.Dst = "198.51.100.21"
	e.Push(other)
	exported, err = e.Export(e.Finish()[0], "test", "overflow")
	if err != nil || exported.Features["unique_peers"] != nil || exported.Quality.Coverage != "gap" {
		t.Fatal("overflow lost", err)
	}
}

func TestPartialBoundsRestartAndDamagedInput(t *testing.T) {
	p := fixture(t, "syn-retry.pcap")[0]
	base, _ := strconv.ParseInt(p.Timestamp, 10, 64)
	start, end := base+1, base+15e9-1
	c := config()
	c.CoverageStart, c.CoverageEnd = &start, &end
	e, _ := New(c)
	for _, offset := range []int64{1, 5e9, 10e9} {
		p.Timestamp = strconv.FormatInt(base+offset, 10)
		out, err := e.Push(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range out {
			if w.Coverage != "partial" {
				t.Fatal("first window claimed complete")
			}
		}
	}
	tail := e.Finish()
	if len(tail) != 2 || tail[0].Coverage != "complete" || tail[1].Coverage != "partial" {
		t.Fatalf("boundaries: %+v", tail)
	}
	e, _ = New(config())
	p = fixture(t, "syn-retry.pcap")[0]
	e.Push(p)
	old := e.Restart()
	if len(old) != 1 || old[0].Coverage != "gap" {
		t.Fatal("restart missing old boundary")
	}
	p.Timestamp = strconv.FormatInt(base+5e9, 10)
	e.Push(p)
	if w := e.Finish()[0]; w.Coverage != "gap" || w.NewTCPAttempts != 1 {
		t.Fatal("restart retained flow history")
	}
	e, _ = New(config())
	p.Status = "truncated"
	e.Push(p)
	w := e.Finish()[0]
	if w.Coverage != "gap" || w.MeanPacketSize != nil {
		t.Fatal("damaged capture treated as normal")
	}
}

func TestLongReplayRetainsBoundedMemory(t *testing.T) {
	e, _ := New(config())
	p := fixture(t, "syn-retry.pcap")[0]
	var baseline runtime.MemStats
	for i := 0; i < 100000; i++ {
		p.Timestamp = strconv.FormatInt(int64(i)*5e9, 10)
		if _, err := e.Push(p); err != nil {
			t.Fatal(err)
		}
		if len(e.queue) > 1 || len(e.windows) > 1 {
			t.Fatal("retained closed history")
		}
		if i == 50000 {
			runtime.GC()
			runtime.ReadMemStats(&baseline)
		}
	}
	e.Finish()
	runtime.GC()
	var end runtime.MemStats
	runtime.ReadMemStats(&end)
	if end.HeapAlloc > baseline.HeapAlloc+16<<20 {
		t.Fatal("memory grows with recording duration")
	}
	t.Logf("live heap after 50k/100k packets: %d / %d bytes", baseline.HeapAlloc, end.HeapAlloc)
	runtime.KeepAlive(e)
}
