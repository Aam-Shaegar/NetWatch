package flow

import (
	"context"
	"io"
	"testing"

	"netwatch.local/netwatch/internal/capture"
	"netwatch.local/netwatch/internal/decode"
)

func packets(t *testing.T, file string) []decode.Meta {
	t.Helper()
	ctx := context.Background()
	src, err := capture.Open(ctx, "../../tests/fixtures/pcap/"+file, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var out []decode.Meta
	for {
		p, err := src.Next(ctx)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
}

func TestDirections(t *testing.T) {
	p := packets(t, "flow-directions.pcap")
	if len(p) != 3 {
		t.Fatalf("got %d packets", len(p))
	}
	var tracker Tracker
	reply, _ := tracker.Observe(p[1]) // Start where the capture sees the server first.
	if reply == nil || reply.FirstFromLow || reply.Attempts != 0 {
		t.Fatalf("unexpected first reply: %+v", reply)
	}
	request, _ := tracker.Observe(p[0])
	if request != reply || request.FirstFromLow || request.Packets != 2 || request.Attempts != 1 {
		t.Fatalf("request did not join the reply: %+v", request)
	}
	udp, _ := tracker.Observe(p[2])
	if udp == nil || udp == request || udp.Attempts != 0 || len(tracker.flows) != 2 {
		t.Fatal("UDP must have its own state")
	}
}

func TestSynRetryCapture(t *testing.T) {
	var tracker Tracker
	for i, p := range packets(t, "syn-retry.pcap") {
		state, retry := tracker.Observe(p)
		if state == nil || retry != (i == 1) || state.Attempts != 1 || state.Established != 0 {
			t.Fatalf("packet %d: state=%+v retry=%v", i, state, retry)
		}
	}
	if len(tracker.flows) != 1 {
		t.Fatalf("got %d flows", len(tracker.flows))
	}
	for _, state := range tracker.flows {
		if !state.FirstFromLow || state.Packets != 2 {
			t.Fatalf("unexpected final state: %+v", state)
		}
	}
}

func TestRetryRequiresSameSenderAndSequence(t *testing.T) {
	p := packets(t, "syn-retry.pcap")[0]
	var tracker Tracker
	tracker.Observe(p)
	seq := *p.TCPSeq + 1
	p.TCPSeq = &seq
	state, retry := tracker.Observe(p)
	if retry || state.Attempts != 2 {
		t.Fatal("different sequence counted as a retry")
	}
	p.Src, p.Dst = p.Dst, p.Src
	p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
	state, retry = tracker.Observe(p)
	if retry || state.Attempts != 3 {
		t.Fatal("opposite sender counted as a retry")
	}
}
