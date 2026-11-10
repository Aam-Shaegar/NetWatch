// Package flow represents transport endpoints observed by the sensor.
package flow

import "net/netip"

// Endpoint converts the IP and optional port from decoded packet metadata.
// A missing port is distinct from an observed port with value zero.
func Endpoint(ip string, port *uint16) (netip.AddrPort, bool) {
	if port == nil {
		return netip.AddrPort{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, *port), true
}

// OrderedEndpoints returns the pair in address, then port order.
func OrderedEndpoints(a, b netip.AddrPort) (netip.AddrPort, netip.AddrPort) {
	if a.Compare(b) > 0 {
		return b, a
	}
	return a, b
}
