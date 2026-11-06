# Packet metadata

Decode the outer IPv4/IPv6 packet only. Ethernet, stacked VLAN tags, TCP, UDP and ICMP are recognized. Bounded IPv6 extension parsing skips hop-by-hop, routing, destination and AH headers. Fragmented packets are counted separately. IPv6 jumbograms are outside the initial profile. TLS/application payloads are never written to JSON.

A truncated record, fragment, malformed packet or non-IP frame has an explicit status and should be excluded from future ML feature extraction. Inspect the import counters to evaluate capture quality. Missing ports remain null. The TCP sequence, acknowledgement number and low eight flag bits are kept for the future flow tracker. `ip_length` counts IP header plus IP payload; `wire_length` includes the link layer.
