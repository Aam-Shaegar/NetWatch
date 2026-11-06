package decode

import (
	"encoding/hex"
	"testing"
)

func FuzzPacket(f *testing.F) {
	seed, _ := hex.DecodeString("6000000000083a4020010db800000000000000000000000120010db80000000000000000000000028000000000000000")
	f.Add(seed)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, p []byte) {
		for _, link := range []int{Ethernet, RawIP} {
			m := Packet(p, link, 0, "test", "0", len(p))
			if m.Status == "decoded" && (m.Src == "" || m.IPLength > len(p)) {
				t.Fatalf("invalid decoded metadata: %+v", m)
			}
		}
	})
}
