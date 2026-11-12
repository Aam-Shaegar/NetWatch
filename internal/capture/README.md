# Offline capture source

`Open(ctx, path, sensorID)` checks container framing and resource bounds. `Next(ctx)` returns one packet's metadata at a time. Use `Close()` when done. The framing check reads record/block headers in a separate pass and does not retain frame bodies. Input must be a stable, uncompressed, regular file up to 256 MiB. Captured frames are limited to 1 MiB and PCAPNG blocks to 4 MiB.

Classic PCAP accepts both byte orders and microsecond or nanosecond timestamps. PCAPNG currently accepts one section, one interface, Enhanced Packet Blocks, decimal clock units from tenths of a second to nanoseconds (default microseconds), and zero time offset. Unsupported layouts return an error. Supported link types are Ethernet and raw IP. Multi-interface and multi-section capture need a richer observation identity before support is added.

Live Linux capture is implemented by `live_linux.go` with CGO/libpcap, explicit interface/BPF, no promiscuous mode, and a 200 ms read poll. `live.go` feeds the existing decoder and can optionally record the exact packets for laboratory replay. Other builds return an explicit unsupported error. See `docs/runbooks/live.md`.
