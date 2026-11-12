package capture

import (
	"context"
	"errors"
	"io"
	"math"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"netwatch.local/netwatch/internal/decode"
)

var ErrTimeout = errors.New("capture poll timeout")

type Stats struct {
	Received         int64 `json:"received"`
	Dropped          int64 `json:"dropped"`
	InterfaceDropped int64 `json:"interface_dropped"`
}

type liveBackend interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Stats() (Stats, error)
	Close()
}

type LiveSource struct {
	backend       liveBackend
	link          int
	sensor, iface string
	record        *pcapgo.Writer
}

func (s *LiveSource) Close()                { s.backend.Close() }
func (s *LiveSource) Stats() (Stats, error) { return s.backend.Stats() }

func (s *LiveSource) Next(ctx context.Context) (decode.Meta, error) {
	if err := ctx.Err(); err != nil {
		return decode.Meta{}, err
	}
	frame, info, err := s.backend.ReadPacketData()
	if err != nil {
		return decode.Meta{}, err
	}
	if err = ctx.Err(); err != nil {
		return decode.Meta{}, err
	}
	if info.Timestamp.Before(time.Unix(0, 0)) || info.Timestamp.After(time.Unix(0, math.MaxInt64)) {
		return decode.Meta{}, errors.New("capture timestamp outside int64")
	}
	if s.record != nil {
		if err = s.record.WritePacket(info, frame); err != nil {
			return decode.Meta{}, err
		}
	}
	// Decoder materializes strings and scalar values before the backend reuses bytes.
	return decode.Packet(frame, s.link, info.Timestamp.UnixNano(), s.sensor, s.iface, info.Length), nil
}

func newLive(backend liveBackend, link int, sensor, iface string, record io.Writer) (*LiveSource, error) {
	if link != decode.Ethernet && link != decode.RawIP {
		return nil, errors.New("unsupported live link type")
	}
	s := &LiveSource{backend: backend, link: link, sensor: sensor, iface: iface}
	if record != nil {
		s.record = pcapgo.NewWriterNanos(record)
		if err := s.record.WriteFileHeader(maxFrame, layers.LinkType(link)); err != nil {
			return nil, err
		}
	}
	return s, nil
}
