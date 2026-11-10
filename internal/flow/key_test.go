package flow_test

import (
	"context"
	"testing"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/flow"
)

func TestKeyFromPacket(t *testing.T) {
	ctx := context.Background()
	src, err := capture.Open(ctx, "../../tests/fixtures/pcap/syn-retry.pcap", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	p, err := src.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := flow.KeyFromPacket(p)
	if !ok {
		t.Fatal("expected a key for the decoded SYN")
	}
	p.Src, p.Dst = p.Dst, p.Src
	p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
	if reverse, ok := flow.KeyFromPacket(p); !ok || reverse != tcp {
		t.Fatal("reversing endpoints changed the TCP key")
	}
	p.Protocol = "UDP"
	if udp, ok := flow.KeyFromPacket(p); !ok || udp == tcp {
		t.Fatal("expected a distinct UDP key for the same endpoints")
	}
	p.DstPort = nil
	if _, ok := flow.KeyFromPacket(p); ok {
		t.Fatal("accepted unobserved destination port")
	}
}
