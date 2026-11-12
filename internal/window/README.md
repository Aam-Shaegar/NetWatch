# Traffic windows

Create one Engine per capture/observation domain and per host or TCP/UDP service.
Use New(Config{Host: host, Lateness: time.Second, MaxUnique: 100000,
MaxPending: 100000}). Service mode requires Service and Protocol instead of Host.

Push returns closed five-second half-open windows aligned to Unix time. Packets
are reordered before flow tracking. The watermark is the greatest input timestamp
minus Lateness. Equal timestamps use serialized metadata for deterministic order.
Packets before the watermark increment the epoch-wide LatePackets counter.
Already returned windows are immutable; the summary and subsequent windows
expose newly discovered late records. LatePackets makes coverage conservative.

Finish drains the tail. Export produces validated traffic-v1 JSON-compatible
objects. Its event ID depends on sensor, epoch, entity and window start.
Only windows with observed traffic or damaged capture records are emitted.

CoverageStart and CoverageEnd optionally declare a continuous observation interval
in nanoseconds, end exclusive. Both are required together. Packets outside the
interval are rejected. Only windows wholly inside it can be complete. Without
that declaration coverage is partial, including the first and last windows.
Damaged records, unavailable unique counts, forced flow evictions and late packets
produce gap. A non-IP frame alone does not indicate lost observation.
CaptureDropped remains null because offline replay cannot measure interface loss.

Restart drains pending windows as gap, clears flow history and the declared
coverage interval, and marks the first subsequent window gap. Callers must use a
new capture_epoch for subsequent Export calls. Restart preserves the time
watermark and starts a new late-packet counter. Packet timestamps must continue
in the same clock domain.

For hosts, source matches count outbound and destination matches count inbound.
For services the configured IP, port and protocol must match. Self-addressed
packets count both directions, but size and timing statistics count each packet
once. Bytes include IP headers. Unique peers are counterpart addresses.
Destination ports count outbound TCP/UDP ports for hosts and the configured
port for services. ICMP does not invent ports.

Connection events are attributed to the packet that first observes the event.
Shared flow state persists across windows. CompletedFlows includes observed
two-sided FIN or RST, not idle expiry. Statistical deviations use population
variance. Interarrival intervals are between consecutive events within a window.
Unavailable denominators produce null. Counts above the exact float64 integer
range are rejected when exporting through the shared contract representation.

Each exact distinct set is limited by MaxUnique. Overflow releases its storage,
sets Count.Overflow, exports null for that count and marks coverage gap. Packet
and byte counts continue. MaxPending bounds the reorder buffer; exceeding it
returns an error without accepting the packet. Callers must stop or handle this
loss explicitly. The engine is single-goroutine. Tests cover a 100,000-packet
recording without retaining closed window history.

For live input, `Advance` closes pending windows after a capture read timeout, using the same clock domain and lateness allowance. It does not synthesize empty windows. The CLI supplies live coverage bounds and capture-drop quality; shutdown tail windows remain partial.
