# Initial window counters

One Engine belongs to one capture/observation domain and one configured host or
TCP/UDP destination service. For example, use New(Config{Host: host,
Lateness: time.Second, MaxUnique: 100000, MaxPending: 100000}).

Push accepts decoded packet metadata and returns windows closed by the capture
watermark (maximum timestamp minus Lateness). Packets are processed in timestamp
order. Equal timestamps use a deterministic serialized-metadata order. Windows
are five-second half-open intervals aligned to Unix time. A packet at the right
boundary belongs to the next window. Packets older than the watermark increment
LatePackets and are discarded without revising published results. Finish drains
the remaining packets and prevents subsequent Push calls.

For a host, destination matches count inbound and source matches count outbound.
For a configured service, its address, port and protocol must match. A response
counts outbound. A self-addressed packet counts in both directions.
Bytes include the IP header. Peers are counterpart IP addresses. Destination
ports are outgoing ports for hosts and the configured port for services.

Count.Value is usable only while Count.Overflow is false. On exceeding MaxUnique,
the individual set releases its storage and marks its count unavailable.
In a future feature-contract adapter, an overflowed count must become null with
an associated quality indication. Packet and byte counters continue.
MaxPending bounds the reorder queue. Exceeding it returns an error and leaves the
new packet unaccepted; callers must abort or explicitly handle the loss.

The result is an intermediate subset, not a full traffic-v1 feature window.
Coverage, remaining statistics and CLI integration are subsequent steps.
Flow attempt counts use the shared flow tracker across window boundaries.
LatePackets is an engine-wide counter because late records may refer to windows
already returned to the caller. The engine must be owned by one goroutine.
