//go:build linux && cgo

package capture

import (
	"os"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestBPFFilterMatchesKnownTraffic(t *testing.T) {
	file, err := os.Open("../../tests/fixtures/pcap/syn-retry.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	data, info, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	for expression, want := range map[string]bool{"tcp port 443": true, "udp port 443": false} {
		filter, err := pcap.NewBPF(layers.LinkTypeEthernet, maxFrame, expression)
		if err != nil || filter.Matches(info, data) != want {
			t.Fatal(expression, err)
		}
	}
	if _, err := pcap.NewBPF(layers.LinkTypeEthernet, maxFrame, "("); err == nil {
		t.Fatal("invalid BPF accepted")
	}
}
