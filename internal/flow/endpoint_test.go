package flow_test

import (
	"context"
	"net/netip"
	"testing"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/flow"
)

func TestEndpointsFromMixedCapture(t *testing.T) {
	ctx := context.Background()
	src, err := capture.Open(ctx, "../../tests/fixtures/pcap/mixed.pcap", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	for i, want := range []string{
		"192.0.2.10:50000", "192.0.2.10:50000", "[2001:db8::1]:50001", "", "192.0.2.11:50002",
	} {
		packet, err := src.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := flow.Endpoint(packet.Src, packet.SrcPort)
		if want == "" {
			if ok || got.IsValid() {
				t.Fatalf("record %d: unexpected endpoint %v", i, got)
			}
		} else if !ok || got != netip.MustParseAddrPort(want) {
			t.Fatalf("record %d: got %v, want %s", i, got, want)
		}
	}
}

func TestEndpointZeroPortAndInvalidIP(t *testing.T) {
	var zero uint16
	if got, ok := flow.Endpoint("192.0.2.1", &zero); !ok || got != netip.MustParseAddrPort("192.0.2.1:0") {
		t.Fatalf("lost observed port zero: %v", got)
	}
	if got, ok := flow.Endpoint("", &zero); ok || got.IsValid() {
		t.Fatalf("accepted missing address: %v", got)
	}
}
