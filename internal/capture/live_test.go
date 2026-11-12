package capture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
)

type fakeLive struct {
	data []byte
	info gopacket.CaptureInfo
	err  error
}

func (f *fakeLive) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return f.data, f.info, f.err
}
func (f *fakeLive) Stats() (Stats, error) { return Stats{Received: 7, Dropped: 2}, nil }
func (f *fakeLive) Close()                {}

func TestLiveDecodesAndRecordsSameFrame(t *testing.T) {
	input, err := os.Open("../../tests/fixtures/pcap/syn-retry.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	reader, err := pcapgo.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	data, info, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeLive{data: data, info: info}
	var raw bytes.Buffer
	source, err := newLive(fake, 1, "sensor", "eth0", &raw)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := source.Next(context.Background())
	if err != nil || packet.Src != "192.0.2.10" || packet.IPLength != 40 || packet.Interface != "eth0" {
		t.Fatalf("decode: %+v %v", packet, err)
	}
	copy(data, make([]byte, len(data)))
	if packet.Src != "192.0.2.10" || *packet.SrcPort != 50000 {
		t.Fatal("retained reused bytes")
	}
	recorded, err := pcapgo.NewReader(&raw)
	if err != nil {
		t.Fatal(err)
	}
	frame, ci, err := recorded.ReadPacketData()
	if err != nil || ci.Timestamp != info.Timestamp || len(frame) != 54 || frame[14] != 0x45 {
		t.Fatal("PCAP snapshot differs", err)
	}
	stats, err := source.Stats()
	if err != nil || stats.Dropped != 2 {
		t.Fatal("lost capture counters")
	}
	fake.err = ErrTimeout
	if _, err = source.Next(context.Background()); !errors.Is(err, ErrTimeout) {
		t.Fatal("timeout hidden")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = source.Next(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored")
	}
}
