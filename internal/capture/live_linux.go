//go:build linux && cgo

package capture

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

type pcapBackend struct{ handle *pcap.Handle }

func (b pcapBackend) Close() { b.handle.Close() }
func (b pcapBackend) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	data, info, err := b.handle.ReadPacketData()
	if err == pcap.NextErrorTimeoutExpired {
		err = ErrTimeout
	}
	return data, info, err
}
func (b pcapBackend) Stats() (Stats, error) {
	v, err := b.handle.Stats()
	if err != nil {
		return Stats{}, err
	}
	return Stats{Received: int64(v.PacketsReceived), Dropped: int64(v.PacketsDropped), InterfaceDropped: int64(v.PacketsIfDropped)}, nil
}

// OpenLive opens a named interface without promiscuous mode. record is optional.
func OpenLive(iface, filter, sensor string, record io.Writer) (*LiveSource, error) {
	if iface == "" || filter == "" || sensor == "" || len(sensor) > 200 {
		return nil, fmt.Errorf("interface, BPF filter and sensor ID are required")
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return nil, err
	}
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()
	if err = inactive.SetSnapLen(maxFrame); err != nil {
		return nil, err
	}
	if err = inactive.SetPromisc(false); err != nil {
		return nil, err
	}
	if err = inactive.SetTimeout(200 * time.Millisecond); err != nil {
		return nil, err
	}
	if err = inactive.SetImmediateMode(true); err != nil {
		return nil, err
	}
	handle, err := inactive.Activate()
	if err != nil {
		return nil, err
	}
	if err = handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}
	source, err := newLive(pcapBackend{handle}, int(handle.LinkType()), sensor, iface, record)
	if err != nil {
		handle.Close()
	}
	return source, err
}
