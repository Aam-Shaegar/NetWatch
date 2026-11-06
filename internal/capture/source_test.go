package capture_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/contract"
	"netwatch.local/netwatch/internal/decode"
)

func fixture(name string) string { return filepath.Join("..", "..", "tests", "fixtures", "pcap", name) }
func read(t *testing.T, name string) []decode.Meta {
	t.Helper()
	ctx := context.Background()
	s, err := capture.Open(ctx, fixture(name), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var rows []decode.Meta
	for {
		p, err := s.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(p)
		if e := contract.Validate("packet", b); e != nil {
			t.Fatal(e)
		}
		rows = append(rows, p)
	}
	return rows
}
func TestEquivalentContainers(t *testing.T) {
	a := read(t, "mixed.pcap")
	b := read(t, "mixed.pcapng")
	if len(a) != 5 || !reflect.DeepEqual(a, b) {
		t.Fatalf("records differ: %v %v", a, b)
	}
	for i, want := range []string{"TCP", "TCP", "UDP", "ICMP", "UDP"} {
		if a[i].Status != "decoded" || a[i].Protocol != want {
			t.Fatalf("record %d: %+v", i, a[i])
		}
	}
	if a[2].Src != "2001:db8::1" || *a[2].DstPort != 53 || a[3].SrcPort != nil || *a[4].DstPort != 53 {
		t.Fatal("IPv6/ICMP/VLAN metadata mismatch")
	}
}
func TestSynRetry(t *testing.T) {
	rows := read(t, "syn-retry.pcap")
	if len(rows) != 2 {
		t.Fatal(len(rows))
	}
	for i, p := range rows {
		if p.Src != "192.0.2.10" || p.Dst != "198.51.100.20" || *p.SrcPort != 50000 || *p.DstPort != 443 || p.IPLength != 40 || *p.TCPFlags != 2 || *p.TCPSeq != 0 {
			t.Fatal(p)
		}
		if p.Timestamp != []string{"1700000000000000000", "1700000001000000000"}[i] {
			t.Fatal(p.Timestamp)
		}
	}
}
func TestExcludedRecords(t *testing.T) {
	for name, status := range map[string]string{"truncated.pcap": "truncated", "fragment.pcap": "fragment"} {
		r := read(t, name)
		if len(r) != 1 || r[0].Status != status {
			t.Fatal(r)
		}
	}
}
func TestInvalidContainers(t *testing.T) {
	for _, name := range []string{"unsupported-linktype.pcap", "malformed.pcap"} {
		if s, e := capture.Open(context.Background(), fixture(name), "test"); e == nil {
			s.Close()
			t.Fatalf("accepted %s", name)
		}
	}
	for _, name := range []string{"mixed.pcap", "mixed.pcapng"} {
		data, _ := os.ReadFile(fixture(name))
		out := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(out, data[:len(data)-1], 0600); err != nil {
			t.Fatal(err)
		}
		if s, e := capture.Open(context.Background(), out, "test"); e == nil {
			s.Close()
			t.Fatalf("accepted incomplete %s", name)
		}
	}
}
func TestCancelledSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := capture.Open(ctx, fixture("mixed.pcap"), "test")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestUnsupportedNGLayout(t *testing.T) {
	data, err := os.ReadFile(fixture("mixed.pcapng"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "two-sections.pcapng")
	if err = os.WriteFile(path, append(data, data...), 0600); err != nil {
		t.Fatal(err)
	}
	if src, e := capture.Open(context.Background(), path, "test"); e == nil {
		src.Close()
		t.Fatal("merged two observation sections")
	}
}
