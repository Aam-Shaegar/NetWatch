package window

import (
	"context"
	"io"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/decode"
)

func fixture(t *testing.T, name string) []decode.Meta {
	t.Helper()
	s, err := capture.Open(context.Background(), "../../tests/fixtures/pcap/"+name, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out []decode.Meta
	for {
		p, err := s.Next(context.Background())
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
}

func config() Config {
	return Config{Host: netip.MustParseAddr("192.0.2.10"), Lateness: time.Second, MaxUnique: 100, MaxPending: 100}
}

func run(t *testing.T, c Config, packets []decode.Meta) []Result {
	t.Helper()
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	var out []Result
	for _, p := range packets {
		r, err := e.Push(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r...)
	}
	return append(out, e.Finish()...)
}

func TestReplayCountersAndOrdering(t *testing.T) {
	p := fixture(t, "syn-retry.pcap")
	a := run(t, config(), p)
	b := run(t, config(), []decode.Meta{p[1], p[0]})
	if !reflect.DeepEqual(a, b) || len(a) != 1 {
		t.Fatalf("reordered results: %v %v", a, b)
	}
	w := a[0]
	if w.OutPackets != 2 || w.OutBytes != 80 || w.InPackets != 0 || w.NewTCPAttempts != 1 || w.ActiveFlows.Value != 1 || w.Peers.Value != 1 || w.DestinationPorts.Value != 1 {
		t.Fatalf("wrong counters: %+v", w)
	}
	p[1].Timestamp = p[0].Timestamp
	if !reflect.DeepEqual(run(t, config(), p), run(t, config(), []decode.Meta{p[1], p[0]})) {
		t.Fatal("equal timestamps must have stable output")
	}
}

func TestServiceDirections(t *testing.T) {
	p := fixture(t, "flow-directions.pcap")
	c := config()
	c.Host = netip.Addr{}
	c.Service = netip.MustParseAddrPort("198.51.100.20:443")
	c.Protocol = "TCP"
	w := run(t, c, p)[0]
	if w.InPackets != 1 || w.OutPackets != 1 || w.InBytes != 40 || w.OutBytes != 40 || w.ActiveFlows.Value != 1 || w.NewTCPAttempts != 1 || w.DestinationPorts.Value != 1 {
		t.Fatalf("wrong service counters or UDP included: %+v", w)
	}
}

func TestBoundaryAndLatePacket(t *testing.T) {
	e, _ := New(config())
	p := fixture(t, "syn-retry.pcap")[0]
	p.Timestamp = "4999999999"
	e.Push(p)
	p.Timestamp = "5000000000"
	e.Push(p)
	p.Timestamp = "6000000000"
	closed, err := e.Push(p)
	if err != nil || len(closed) != 1 || closed[0].Start != 0 || closed[0].End != width || closed[0].OutPackets != 1 {
		t.Fatalf("wrong closed window: %v %v", closed, err)
	}
	p.Timestamp = "4999999999"
	e.Push(p)
	if e.LatePackets != 1 {
		t.Fatal("missing late counter")
	}
	tail := e.Finish()
	if len(tail) != 1 || tail[0].Start != width || tail[0].OutPackets != 2 {
		t.Fatalf("boundary packet in wrong window: %v", tail)
	}
}

func TestDistinctOverflowAndInputOwnership(t *testing.T) {
	p := fixture(t, "syn-retry.pcap")
	c := config()
	c.MaxUnique = 1
	p[1].Dst = "198.51.100.21"
	port := uint16(80)
	p[1].DstPort = &port
	w := run(t, c, p)[0]
	if !w.Peers.Overflow || !w.DestinationPorts.Overflow || !w.ActiveFlows.Overflow || w.OutPackets != 2 {
		t.Fatalf("silent truncation: %+v", w)
	}
	e, _ := New(config())
	p = fixture(t, "syn-retry.pcap")
	e.Push(p[0])
	*p[0].TCPFlags = 16
	*p[0].TCPSeq = 99
	*p[0].DstPort = 80
	e.Push(p[1])
	if got := e.Finish()[0]; got.NewTCPAttempts != 1 || got.ActiveFlows.Value != 1 {
		t.Fatalf("buffer retained caller-owned pointers: %+v", got)
	}
}

func TestLimitsAndValidation(t *testing.T) {
	c := config()
	c.MaxPending = 1
	e, _ := New(c)
	p := fixture(t, "syn-retry.pcap")[0]
	e.Push(p)
	if _, err := e.Push(p); err == nil {
		t.Fatal("missing buffer limit")
	}
	if got := e.Finish(); len(got) != 1 || got[0].OutPackets != 1 {
		t.Fatal("failed push changed state")
	}
	if _, err := e.Push(p); err == nil {
		t.Fatal("push after finish")
	}
	for _, timestamp := range []string{"bad", "-1", strconv.FormatInt(math.MaxInt64, 10)} {
		e, _ = New(config())
		p.Timestamp = timestamp
		if _, err := e.Push(p); err == nil {
			t.Fatal("accepted invalid time", timestamp)
		}
	}
	c = config()
	c.Lateness = -1
	if _, err := New(c); err == nil {
		t.Fatal("accepted negative lateness")
	}
	c = config()
	c.Service = netip.MustParseAddrPort("198.51.100.20:443")
	if _, err := New(c); err == nil {
		t.Fatal("accepted ambiguous entity")
	}
}

func TestIPv6AndICMP(t *testing.T) {
	p := fixture(t, "mixed.pcap")
	c := config()
	c.Host = netip.MustParseAddr("2001:db8::1")
	w := run(t, c, p)[0]
	if w.OutPackets != 1 || w.OutBytes != 48 || w.ActiveFlows.Value != 1 || w.DestinationPorts.Value != 1 {
		t.Fatalf("IPv6 counts: %+v", w)
	}
	w = run(t, config(), []decode.Meta{p[3]})[0]
	if w.OutPackets != 1 || w.Peers.Value != 1 || w.DestinationPorts.Value != 0 || w.ActiveFlows.Value != 0 {
		t.Fatalf("ICMP invented transport ports: %+v", w)
	}
}
