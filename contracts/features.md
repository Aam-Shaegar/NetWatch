# Feature contract traffic-v1 — initial subset

Go window aggregation emits this schema through sensor replay with --host or --service.
Entity host: in = destination is host, out = source is host. destination_service:
in = client to configured service, out = response. TCP/UDP ports absent → null in PacketMeta.
Window is [start,end), 5 seconds by default. JSON times are decimal int64 ns strings.
Counts are exact nonnegative integers semantically, serialized as JSON numbers; rates will have explicit fields in a later version.
IP bytes include network header, exclude link header. Packet size statistics use both directions.
Unique peers = counterpart IPs; unique_destination_ports = outgoing TCP/UDP ports for host,
configured destination ports for service. No absent-port sentinel counted as a real port.
Active flows = distinct bidirectional flows observed in window. New TCP attempts count a
new SYN without ACK once per flow incarnation, not retransmitted SYN. Established attempts
require an observed handshake. SYN/RST fractions use all TCP packets as denominator.
Interarrival statistics use sorted observed entity packet times in seconds; population std.
If fewer than 2 events, interarrival mean/std are null. No valid denominator → null.
Completed flow count requires observed close; censored flows are not completed.
Unavailable features are null, never fabricated zero. No model training until full feature golden tests pass.
Capture drops null means unknown, zero means measured zero. coverage gap prevents inference.
Go and Python enforce end > start, signed int64 range and integer count fields.
Prediction normal/anomalous needs finite nonnull score and threshold; other states carry null scores.
Unknown properties and future schema versions are rejected, not silently accepted.

The example host window represents the two SYN packets in `tests/fixtures/pcap/syn-retry.pcap`: one flow, one attempt, 80 outbound IP bytes and SYN fraction 1. Its declared complete coverage describes a controlled 5 s observation, not evidence of coverage inferred from the file boundary.

When continuous capture is verified, every fully covered five-second interval
has a window, including zero traffic. Statistical quantities without samples
remain null. Live capture advances the watermark on read timeouts. Capture
loss is attributed to windows intersecting the interval between stats polls.
Late packets increment the epoch total and flag their still-open window, or
the first open window if their original window has already been published.

## traffic-v2 TCP connection ages

`traffic-v2` keeps the original columns and adds five required, nullable
measurements. Live capture and offline replay both use the Go window engine.

- `tcp_age_mean_seconds` and `tcp_age_max_seconds` are computed from one
  sample per TCP connection incarnation with packets in the window. Each
  sample spans the first observed opening SYN to its last observed packet
  in the window, up to and including an observed close.
- `tcp_closed_duration_mean_seconds` and `tcp_closed_duration_max_seconds`
  use only connections with a known opening and a first observed RST or
  FIN from both directions in this window.
- `tcp_age_known_start_fraction` gives the fraction of sampled TCP
  incarnations with a trusted opening SYN. It is null without samples.
  The age and closure statistics are null when their respective samples
  are unavailable.

Same-sequence SYN retransmissions keep the original opening time. Quiet
connections contribute when another packet is observed before the tracker
expires their idle state (60 seconds between TCP packets). Expiration is
censoring. A capture started mid-connection, a bounded state eviction, a
capture gap, or a new epoch can make an opening time unavailable. The window
still carries its quality flags, and incomplete observations cannot yield a
scored prediction. Durations measure the transport connection.
