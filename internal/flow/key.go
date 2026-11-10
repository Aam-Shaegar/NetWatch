package flow

import (
	"net/netip"

	"netwatch.local/netwatch/internal/decode"
)

// Key identifies a TCP or UDP exchange in either direction.
type Key struct {
	protocol  string
	low, high netip.AddrPort
}

func KeyFromPacket(p decode.Meta) (Key, bool) {
	key, _, ok := packetKey(p)
	return key, ok
}

func packetKey(p decode.Meta) (Key, bool, bool) {
	if p.Status != "decoded" || (p.Protocol != "TCP" && p.Protocol != "UDP") {
		return Key{}, false, false
	}
	src, srcOK := Endpoint(p.Src, p.SrcPort)
	dst, dstOK := Endpoint(p.Dst, p.DstPort)
	if !srcOK || !dstOK {
		return Key{}, false, false
	}
	low, high := OrderedEndpoints(src, dst)
	return Key{protocol: p.Protocol, low: low, high: high}, src == low, true
}
