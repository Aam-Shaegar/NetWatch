// Package capture reads uncompressed captures. A bounded framing pass detects
// incomplete records before GoPacket reads them; neither pass retains the file.
package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"netwatch.local/netwatch/internal/decode"
)

const maxFile = 256 << 20
const maxFrame = 1 << 20
const maxBlock = 4 << 20

type reader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}
type Source struct {
	file   *os.File
	reader reader
	link   int
	sensor string
}

func (s *Source) Close() error { return s.file.Close() }
func Open(ctx context.Context, path, sensor string) (*Source, error) {
	if sensor == "" || len(sensor) > 200 {
		return nil, fmt.Errorf("invalid sensor ID")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := open(ctx, f, sensor)
	if err != nil {
		f.Close()
	}
	return s, err
}
func open(ctx context.Context, f *os.File, sensor string) (*Source, error) {
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > maxFile {
		return nil, errors.New("expected regular file up to 256 MiB")
	}
	var magic [4]byte
	if _, err = f.ReadAt(magic[:], 0); err != nil {
		return nil, fmt.Errorf("capture header: %w", err)
	}
	s := &Source{file: f, sensor: sensor}
	ng := binary.BigEndian.Uint32(magic[:]) == 0x0a0d0d0a
	if ng {
		if err = checkNG(ctx, f, stat.Size()); err != nil {
			return nil, err
		}
		r, e := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
		if e != nil {
			return nil, e
		}
		s.link = int(r.LinkType())
		s.reader = r
	} else {
		if err = checkPCAP(ctx, f, stat.Size(), magic); err != nil {
			return nil, err
		}
		r, e := pcapgo.NewReader(f)
		if e != nil {
			return nil, e
		}
		s.link = int(r.LinkType())
		s.reader = r
	}
	if s.link != decode.Ethernet && s.link != decode.RawIP {
		return nil, fmt.Errorf("unsupported link type %d", s.link)
	}
	return s, nil
}
func (s *Source) Next(ctx context.Context) (decode.Meta, error) {
	if err := ctx.Err(); err != nil {
		return decode.Meta{}, err
	}
	frame, ci, err := s.reader.ReadPacketData()
	if err != nil {
		return decode.Meta{}, err
	}
	if ci.Timestamp.Before(time.Unix(0, 0)) || ci.Timestamp.After(time.Unix(0, math.MaxInt64)) {
		return decode.Meta{}, errors.New("timestamp outside supported range")
	}
	return decode.Packet(frame, s.link, ci.Timestamp.UnixNano(), s.sensor, "0", ci.Length), nil
}
func checkPCAP(ctx context.Context, f io.ReaderAt, size int64, magic [4]byte) error {
	var order binary.ByteOrder = binary.LittleEndian
	var limit uint32 = 1_000_000
	switch binary.BigEndian.Uint32(magic[:]) {
	case 0xa1b2c3d4:
		order = binary.BigEndian
	case 0xd4c3b2a1:
	case 0xa1b23c4d:
		order = binary.BigEndian
		limit = 1_000_000_000
	case 0x4d3cb2a1:
		limit = 1_000_000_000
	default:
		return errors.New("unrecognized capture magic")
	}
	var h [24]byte
	if _, err := f.ReadAt(h[:], 0); err != nil {
		return err
	}
	link := order.Uint32(h[20:])
	if link != decode.Ethernet && link != decode.RawIP {
		return fmt.Errorf("unsupported link type %d", link)
	}
	for pos := int64(24); pos < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := f.ReadAt(h[:16], pos); err != nil {
			return fmt.Errorf("incomplete record header at %d", pos)
		}
		caplen := order.Uint32(h[8:12])
		if order.Uint32(h[4:8]) >= limit || caplen > maxFrame || caplen > order.Uint32(h[12:16]) || int64(caplen) > size-pos-16 {
			return fmt.Errorf("invalid record at %d", pos)
		}
		pos += 16 + int64(caplen)
	}
	return nil
}

// M0 explicitly accepts one PCAPNG section and one interface, with Enhanced
// Packet Blocks. Reject unsupported layouts instead of merging their traffic.
func checkNG(ctx context.Context, f io.ReaderAt, size int64) error {
	var h [28]byte
	var order binary.ByteOrder
	interfaces := 0
	for pos := int64(0); pos < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := f.ReadAt(h[:12], pos); err != nil {
			return errors.New("incomplete pcapng block")
		}
		if binary.BigEndian.Uint32(h[:4]) == 0x0a0d0d0a {
			if pos != 0 {
				return errors.New("multiple pcapng sections unsupported")
			}
			switch binary.BigEndian.Uint32(h[8:12]) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return errors.New("invalid byte order magic")
			}
		}
		if order == nil {
			return errors.New("missing section header")
		}
		kind := order.Uint32(h[:4])
		n := int64(order.Uint32(h[4:8]))
		if n < 12 || n%4 != 0 || n > maxBlock || n > size-pos {
			return fmt.Errorf("invalid pcapng block length at %d", pos)
		}
		var tail [4]byte
		if _, err := f.ReadAt(tail[:], pos+n-4); err != nil || int64(order.Uint32(tail[:])) != n {
			return errors.New("pcapng length trailer mismatch")
		}
		switch kind {
		case 0x0a0d0d0a:
			if n < 28 {
				return errors.New("short section header")
			}
		case 1:
			interfaces++
			if interfaces != 1 || n < 20 {
				return errors.New("expected exactly one pcapng interface")
			}
			opts := make([]byte, n-20)
			if len(opts) > 0 {
				if _, err := f.ReadAt(opts, pos+16); err != nil {
					return err
				}
			}
			if err := checkInterfaceOptions(opts, order); err != nil {
				return err
			}
		case 6:
			if interfaces != 1 || n < 32 {
				return errors.New("invalid enhanced packet block")
			}
			if _, err := f.ReadAt(h[:28], pos); err != nil {
				return err
			}
			caplen := order.Uint32(h[20:24])
			if order.Uint32(h[8:12]) != 0 || caplen > maxFrame || caplen > order.Uint32(h[24:28]) || int64(caplen) > n-32 {
				return errors.New("invalid enhanced packet length/interface")
			}
		case 4, 5: // Name resolution and interface statistics: no packets.
		default:
			return fmt.Errorf("unsupported pcapng block type %d", kind)
		}
		pos += n
	}
	if interfaces != 1 {
		return errors.New("missing pcapng interface")
	}
	return nil
}

// Limit the initial profile to exact decimal clock units up to nanoseconds.
// This avoids silently rounding clocks that the selected backend approximates.
func checkInterfaceOptions(opts []byte, order binary.ByteOrder) error {
	for len(opts) > 0 {
		if len(opts) < 4 {
			return errors.New("incomplete interface option")
		}
		code := order.Uint16(opts[:2])
		length := int(order.Uint16(opts[2:4]))
		padded := (length + 3) &^ 3
		if padded > len(opts)-4 {
			return errors.New("truncated interface option")
		}
		value := opts[4 : 4+length]
		switch code {
		case 0:
			if length != 0 {
				return errors.New("invalid end option")
			}
			return nil
		case 9:
			if length != 1 || value[0] < 1 || value[0] > 9 {
				return errors.New("unsupported pcapng clock resolution")
			}
		case 14:
			if length != 8 || order.Uint64(value) != 0 {
				return errors.New("nonzero pcapng clock offset unsupported")
			}
		}
		opts = opts[4+padded:]
	}
	return nil
}
