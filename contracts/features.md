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
