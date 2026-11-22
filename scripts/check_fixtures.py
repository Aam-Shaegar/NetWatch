"""Check the packaged capture files against their recorded hashes and packet counts."""

import hashlib
import json
from pathlib import Path

from scapy.all import Dot1Q, ICMP, IP, IPv6, TCP, UDP, rdpcap


FIXTURES = Path(__file__).resolve().parents[1] / "tests/fixtures/pcap"


def main():
    expected = json.loads((FIXTURES / "expected.json").read_text())
    for name, digest in expected["sha256"].items():
        assert hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest() == digest, name

    counts = expected["mixed"]
    layers = {"ipv4": IP, "ipv6": IPv6, "tcp": TCP, "udp": UDP, "icmp": ICMP, "vlan": Dot1Q}
    for name in ("mixed.pcap", "mixed.pcapng"):
        packets = rdpcap(str(FIXTURES / name))
        assert len(packets) == counts["record_count"], name
        for protocol, layer in layers.items():
            assert sum(layer in packet for packet in packets) == counts[protocol], (name, protocol)
        assert [packet[IP].len for packet in packets[:2]] == counts["first_two_tcp_ip_lengths"], name
    print("PCAP fixture counts and hashes verified")


if __name__ == "__main__":
    main()
