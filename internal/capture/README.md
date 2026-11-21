# Offline capture source

`Open(ctx, path, sensorID)` checks container framing and resource bounds. `Next(ctx)` returns one packet's metadata at a time. Use `Close()` when done. The framing check reads record/block headers in a separate pass and does not retain frame bodies. Input must be a stable, uncompressed, regular file of any size. Captured frames are limited to 1 MiB and PCAPNG blocks to 4 MiB.

Classic PCAP accepts both byte orders and microsecond or nanosecond timestamps. PCAPNG currently accepts one section, one interface, Enhanced Packet Blocks, decimal clock units from tenths of a second to nanoseconds (default microseconds), and zero time offset. Unsupported layouts return an error. Supported link types are Ethernet, raw IP, and BSD loopback headers. Multi-interface and multi-section capture need a richer observation identity before support is added.

Live capture on Linux and macOS uses `live_pcap.go` with CGO/libpcap, an explicit interface and BPF, no promiscuous mode, and a configured 200 ms read timeout. `live.go` feeds the existing decoder and can optionally record the exact packets for laboratory replay. Other builds return an explicit unsupported error. See `docs/runbooks/live.md`.
