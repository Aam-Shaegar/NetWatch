package flow

import (
	"testing"
	"time"
)

func TestHandshakeAndClose(t *testing.T) {
	p := packets(t, "flow-directions.pcap")
	syn, reply := p[0], p[1]
	final := syn
	flags, seq, ack := uint8(16), *syn.TCPSeq+1, *reply.TCPSeq+1
	final.TCPFlags, final.TCPSeq, final.TCPAck = &flags, &seq, &ack
	var tracker Tracker
	state, _ := tracker.Observe(syn)
	tracker.Observe(reply)
	if state.Established != 0 {
		t.Fatal("capture ends before the final ACK")
	}
	ack++
	tracker.Observe(final)
	ack--
	seq++
	tracker.Observe(final)
	seq--
	if state.Established != 0 {
		t.Fatal("accepted mismatched final ACK")
	}
	tracker.Observe(final)
	tracker.Observe(final)
	if state.Established != 1 {
		t.Fatal("expected exactly one observed handshake")
	}
	flags = 17 // FIN+ACK
	tracker.Observe(final)
	tracker.Observe(final)
	if state.ClosedBy != "" {
		t.Fatal("one-sided FIN closed both directions")
	}
	reply.TCPFlags = &flags
	tracker.Observe(reply)
	if state.ClosedBy != "fin" {
		t.Fatal("missing orderly close")
	}
	fresh, retry := tracker.Observe(syn)
	if fresh == state || retry || fresh.Attempts != 1 || fresh.Established != 0 {
		t.Fatal("reused tuple inherited closed state")
	}
	flags = 4 // RST
	tracker.Observe(reply)
	if fresh.ClosedBy != "rst" {
		t.Fatal("missing reset")
	}
}

func TestReplyMustMatchOpening(t *testing.T) {
	p := packets(t, "flow-directions.pcap")
	var tracker Tracker
	state, _ := tracker.Observe(p[0])
	reply := p[1]
	bad := *reply.TCPAck + 1
	reply.TCPAck = &bad
	tracker.Observe(reply)
	reply = p[1]
	reply.Src, reply.Dst = reply.Dst, reply.Src
	reply.SrcPort, reply.DstPort = reply.DstPort, reply.SrcPort
	tracker.Observe(reply)
	if state.reply[0] != nil || state.reply[1] != nil {
		t.Fatal("accepted unmatched SYN+ACK")
	}
}

func TestIdleExpiry(t *testing.T) {
	p := packets(t, "flow-directions.pcap")
	var tracker Tracker
	tcp, _ := tracker.Observe(p[0])
	udp, _ := tracker.Observe(p[2])
	tracker.Advance(udp.last + int64(30*time.Second) - 1)
	if len(tracker.flows) != 2 {
		t.Fatal("expired early")
	}
	tracker.Advance(udp.last + int64(30*time.Second))
	if len(tracker.flows) != 1 || tcp.entry == nil {
		t.Fatal("expected only TCP to survive")
	}
	tracker.Advance(tcp.last + int64(60*time.Second))
	if len(tracker.flows) != 0 || tracker.StateEvictions != 0 {
		t.Fatal("idle expiry counted as forced eviction or left stale state")
	}
}

func TestCapacityEvictsOldest(t *testing.T) {
	p := packets(t, "flow-directions.pcap")
	tracker := Tracker{limit: 2}
	tcp, _ := tracker.Observe(p[0])
	udp, _ := tracker.Observe(p[2])
	refreshed := p[0]
	refreshed.Timestamp = "1700000003000000000"
	tracker.Observe(refreshed)
	port := uint16(444)
	refreshed.DstPort = &port
	tracker.Observe(refreshed)
	if len(tracker.flows) != 2 || tcp.entry == nil || udp.entry != nil || tracker.StateEvictions != 1 {
		t.Fatal("wrong eviction or quality counter")
	}
}
