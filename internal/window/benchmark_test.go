package window

import (
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"netwatch.local/netwatch/internal/decode"
)

// Represents already-decoded metadata, routed to the configured entity in memory.
func BenchmarkServiceWindows(b *testing.B) {
	const entities = 100
	const flows = 1000
	const perSecond = 10000
	engines := make([]*Engine, entities)
	packets := make([]decode.Meta, flows)
	destPort := uint16(8080)
	for i := range entities {
		addr := netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i+1))
		engine, err := New(Config{Service: netip.AddrPortFrom(addr, destPort), Protocol: "TCP", Lateness: time.Second, MaxUnique: 4096, MaxPending: 4096})
		if err != nil {
			b.Fatal(err)
		}
		engines[i] = engine
		for j := i; j < flows; j += entities {
			srcPort := uint16(15000 + j)
			packets[j] = decode.Meta{Src: "198.51.100.1", Dst: addr.String(), Protocol: "TCP", SrcPort: &srcPort, DstPort: &destPort,
				Status: "decoded", IPLength: []int{64, 512, 1500}[j%3]}
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := packets[i%flows]
		p.Timestamp = strconv.FormatInt(int64(i)*(int64(time.Second)/perSecond), 10)
		if _, err := engines[i%entities].Push(p); err != nil {
			b.Fatal(err)
		}
	}
	for _, e := range engines {
		e.Finish()
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "packets/s")
}
