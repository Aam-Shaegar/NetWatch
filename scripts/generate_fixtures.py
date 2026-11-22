"""Build the small packet captures used by the decoder tests."""

import hashlib
import json
from pathlib import Path
import struct

from scapy.all import Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap
from scapy.utils import PcapNgWriter


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/pcap"
START = 1_700_000_000


def pcap_header(link_type):
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)


def main():
    FIXTURES.mkdir(parents=True, exist_ok=True)
    client, server = "192.0.2.10", "198.51.100.20"
    ethernet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    request = ethernet / IP(src=client, dst=server)
    syn = request / TCP(sport=50000, dport=443, flags="S")
    frames = [
        syn,
        syn.copy(),
        ethernet / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=50001, dport=53),
        request / ICMP(),
        ethernet / Dot1Q(vlan=7) / IP(src="192.0.2.11", dst=server) / UDP(sport=50002, dport=53),
    ]
    for index, packet in enumerate(frames):
        packet.time = START + index

    wrpcap(str(FIXTURES / "mixed.pcap"), frames)
    wrpcap(str(FIXTURES / "syn-retry.pcap"), frames[:2])
    with PcapNgWriter(str(FIXTURES / "mixed.pcapng")) as writer:
        for packet in frames:
            writer.write(packet)

    # Reverse the TCP endpoints, then reuse the original pair over UDP.
    reply = (
        Ether(src=ethernet.dst, dst=ethernet.src)
        / IP(src=server, dst=client)
        / TCP(sport=443, dport=50000, flags="SA", seq=19, ack=1)
    )
    udp = request / UDP(sport=50000, dport=443)
    reply.time, udp.time = START + 1, START + 2
    wrpcap(str(FIXTURES / "flow-directions.pcap"), [syn, reply, udp])

    fragment = ethernet / IP(src=client, dst=server, flags="MF") / UDP(sport=1, dport=2) / Raw(b"12345678")
    fragment.time = START
    wrpcap(str(FIXTURES / "fragment.pcap"), [fragment])

    # The record advertises the full wire length but contains only the first 30 bytes.
    raw = bytes(syn)
    record = struct.pack("<IIII", START, 0, 30, len(raw)) + raw[:30]
    (FIXTURES / "truncated.pcap").write_bytes(pcap_header(1) + record)
    (FIXTURES / "unsupported-linktype.pcap").write_bytes(pcap_header(65000))
    (FIXTURES / "malformed.pcap").write_bytes(b"not a pcap file")

    expected = {
        "purpose": "decoder fixtures, not training data",
        "mixed": {
            "record_count": 5,
            "ipv4": 4,
            "ipv6": 1,
            "tcp": 2,
            "udp": 2,
            "icmp": 1,
            "vlan": 1,
            "first_two_tcp_ip_lengths": [40, 40],
            "first_two_tcp_unique_flows": 1,
            "first_two_tcp_new_attempts": 1,
            "timestamps_seconds": [START + i for i in range(5)],
        },
        "sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(FIXTURES.glob("*.pcap*"))
        },
    }
    (FIXTURES / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
    print(FIXTURES)


if __name__ == "__main__":
    main()
