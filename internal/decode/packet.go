// Package decode extracts outer IP metadata. It never retains packet payloads.
package decode

import (
	"encoding/binary"
	"net/netip"
	"strconv"
)

const (
	Ethernet = 1
	RawIP    = 101
)

// Meta follows contracts/packet.schema.json. Null ports mean not observed.
type Meta struct {
	Version   int     `json:"schema_version"`
	Sensor    string  `json:"sensor_id"`
	Interface string  `json:"interface_id"`
	Timestamp string  `json:"timestamp_ns"`
	Src       string  `json:"src_ip"`
	Dst       string  `json:"dst_ip"`
	Protocol  string  `json:"protocol"`
	SrcPort   *uint16 `json:"src_port"`
	DstPort   *uint16 `json:"dst_port"`
	IPLength  int     `json:"ip_length"`
	Status    string  `json:"decode_status"`
	Captured  int     `json:"captured_length"`
	Wire      int     `json:"wire_length"`
	TCPFlags  *uint8  `json:"tcp_flags,omitempty"`
	TCPSeq    *uint32 `json:"tcp_seq,omitempty"`
	TCPAck    *uint32 `json:"tcp_ack,omitempty"`
}

func Packet(frame []byte, link int, ns int64, sensor, iface string, wire int) Meta {
	m := Meta{Version: 1, Sensor: sensor, Interface: iface, Timestamp: strconv.FormatInt(ns, 10), Protocol: "OTHER", Status: "malformed", Captured: len(frame), Wire: wire}
	if len(frame) < wire {
		m.Status = "truncated"
		return m
	}
	switch link {
	case Ethernet:
		if len(frame) < 14 {
			return m
		}
		typ := binary.BigEndian.Uint16(frame[12:14])
		frame = frame[14:]
		for typ == 0x8100 || typ == 0x88a8 {
			if len(frame) < 4 {
				return m
			}
			typ = binary.BigEndian.Uint16(frame[2:4])
			frame = frame[4:]
		}
		if typ != 0x0800 && typ != 0x86dd {
			m.Status = "non_ip"
			return m
		}
		if len(frame) == 0 || (typ == 0x0800 && frame[0]>>4 != 4) || (typ == 0x86dd && frame[0]>>4 != 6) {
			return m
		}
	case RawIP:
	default:
		m.Status = "unsupported_linktype"
		return m
	}
	if len(frame) == 0 {
		return m
	}
	switch frame[0] >> 4 {
	case 4:
		m.ipv4(frame)
	case 6:
		m.ipv6(frame)
	}
	return m
}

func (m *Meta) ipv4(p []byte) {
	if len(p) < 20 {
		return
	}
	h := int(p[0]&15) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if h < 20 || total < h {
		return
	}
	m.IPLength = total
	m.Src = netip.AddrFrom4([4]byte(p[12:16])).String()
	m.Dst = netip.AddrFrom4([4]byte(p[16:20])).String()
	if len(p) < total {
		m.Status = "truncated"
		return
	}
	if binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		m.Status = "fragment"
		return
	}
	m.transport(p[9], p[h:total])
}
func (m *Meta) ipv6(p []byte) {
	if len(p) < 40 {
		return
	}
	total := 40 + int(binary.BigEndian.Uint16(p[4:6]))
	m.IPLength = total
	m.Src = netip.AddrFrom16([16]byte(p[8:24])).String()
	m.Dst = netip.AddrFrom16([16]byte(p[24:40])).String()
	if len(p) < total {
		m.Status = "truncated"
		return
	}
	next := p[6]
	body := p[40:total]
	for n := 0; n < 16; n++ {
		switch next {
		case 44:
			m.Status = "fragment"
			return
		case 0, 43, 60, 51:
			if len(body) < 2 {
				return
			}
			length := (int(body[1]) + 1) * 8
			if next == 51 {
				length = (int(body[1]) + 2) * 4
			}
			if length > len(body) {
				return
			}
			next, body = body[0], body[length:]
		default:
			m.transport(next, body)
			return
		}
	}
}
func (m *Meta) transport(proto byte, p []byte) {
	switch proto {
	case 6:
		if len(p) < 20 {
			return
		}
		off := int(p[12]>>4) * 4
		if off < 20 || off > len(p) {
			return
		}
		m.Protocol = "TCP"
		flags := p[13]
		seq := binary.BigEndian.Uint32(p[4:8])
		ack := binary.BigEndian.Uint32(p[8:12])
		m.TCPFlags = &flags
		m.TCPSeq = &seq
		m.TCPAck = &ack
	case 17:
		if len(p) < 8 {
			return
		}
		length := int(binary.BigEndian.Uint16(p[4:6]))
		if length < 8 || length > len(p) {
			return
		}
		m.Protocol = "UDP"
	case 1, 58:
		if len(p) < 4 {
			return
		}
		m.Protocol = "ICMP"
	}
	if proto == 6 || proto == 17 {
		s, d := binary.BigEndian.Uint16(p[:2]), binary.BigEndian.Uint16(p[2:4])
		m.SrcPort = &s
		m.DstPort = &d
	}
	m.Status = "decoded"
}
