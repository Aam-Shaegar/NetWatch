"""Offline episode benchmark for the packet-labelled Kitsune Ethernet captures."""

import argparse
from collections import Counter, defaultdict
import csv
from dataclasses import dataclass, field
import hashlib
from itertools import zip_longest
import json
from pathlib import Path
import socket
import struct
import sys

from scapy.utils import RawPcapReader

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))
from netwatch_ml.bursts import BurstRates
from netwatch_ml.handshakes import Handshakes
from netwatch_ml.security import RULES, assess, with_reference

SCENARIOS = {
    "OS_Scan": ["port_scan"],
    "SSDP_Flood": ["udp_flood", "packet_flood"],
    "SYN_DoS": ["syn_flood", "packet_flood", "dos"],
    "ARP_MitM": ["possible_mitm"],
}


@dataclass
class Host:
    packets: Counter = field(default_factory=Counter)
    ports: dict = field(default_factory=lambda: defaultdict(set))
    burst: BurstRates = field(default_factory=BurstRates)
    tcp: Handshakes = field(default_factory=Handshakes)

    def metrics(self):
        total = self.packets.total()
        data = dict(
            in_pps=total / 60,
            max_ports_one_peer=max(map(len, self.ports.values()), default=0),
            source_ips=len(self.ports),
            **self.tcp.metrics(),
            **self.burst.metrics(),
        )
        if total:
            data.update(
                udp_fraction=self.packets[17] / total,
                icmp_fraction=self.packets[1] / total,
            )
        return data


def observe(hosts, frame, ts):
    # Kitsune truncates payloads. Only complete Ethernet/IPv4 and transport headers are used.
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 15) * 4
    if ihl < 20 or frame[14] >> 4 != 4 or len(frame) < 14 + ihl:
        raise ValueError("short IPv4 header")
    src, dst = frame[26:30], frame[30:34]
    proto = frame[23]
    host = hosts[dst]
    host.burst.add(ts, {17: "UDP", 1: "ICMP"}.get(proto))
    host.packets[proto] += 1
    ports = host.ports[src]
    offset = 14 + ihl
    if proto not in (6, 17) or int.from_bytes(frame[20:22], "big") & 0x1FFF:
        return dst
    if len(frame) < offset + (20 if proto == 6 else 8):
        raise ValueError("short transport header")
    sport, dport = struct.unpack_from("!HH", frame, offset)
    ports.add(dport)
    if proto == 6:
        flags = frame[offset + 13]
        seq, ack = struct.unpack_from("!II", frame, offset + 4)
        host.tcp.observe(True, src, sport, dport, flags, seq, ack)
        if flags & 0x16 == 0x12:
            hosts[src].tcp.observe(False, dst, dport, sport, flags, seq, ack)
    return dst


def score(hosts, reference, start):
    alerts, available = defaultdict(set), defaultdict(set)
    for ip in hosts.keys() | set().union(*reference):
        metrics = hosts[ip].metrics() if ip in hosts else Host().metrics()
        empty = Host().metrics()
        metrics = with_reference(
            metrics, [minute.get(ip, empty) for minute in reference]
        )
        result = assess(
            dict(
                schema_version=1,
                entity=socket.inet_ntoa(ip),
                start_s=start,
                interval_s=60,
                metrics=metrics,
            )
        )
        for label in RULES.keys() - result["unassessed"].keys():
            available[label].add(ip)
        for finding in result["findings"]:
            alerts[finding["label"]].add(ip)
    return alerts, available


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def sensor_packets(sensor, pcap):
    import subprocess

    with subprocess.Popen(
        [str(sensor.resolve()), "replay", "--input", str(pcap), "--output", "-"],
        stdout=subprocess.PIPE,
    ) as proc:
        try:
            for line in proc.stdout:
                yield json.loads(line)
        finally:
            proc.stdout.close()
        if proc.wait():
            raise ValueError("sensor replay failed")


def observe_metadata(hosts, packet, ts):
    if packet["decode_status"] == "non_ip":
        return None
    if packet["decode_status"] not in ("decoded", "fragment") and not packet.get(
        "header_complete"
    ):
        raise ValueError("unobservable packet in sensor replay")
    if ":" in packet["dst_ip"]:
        return None  # This labelled benchmark is defined for IPv4 targets.
    dst, src = map(socket.inet_aton, (packet["dst_ip"], packet["src_ip"]))
    host = hosts[dst]
    proto = packet["protocol"]
    host.packets[{"TCP": 6, "UDP": 17, "ICMP": 1}.get(proto, 0)] += 1
    host.burst.add(ts, proto)
    ports = host.ports[src]
    sport, dport = packet["src_port"], packet["dst_port"]
    if dport is not None:
        ports.add(dport)
    if proto == "TCP" and packet["decode_status"] == "fragment":
        host.tcp.observable = False
    elif proto == "TCP":
        flags, seq, ack = (packet[k] for k in ("tcp_flags", "tcp_seq", "tcp_ack"))
        host.tcp.observe(True, src, sport, dport, flags, seq, ack)
        if flags & 0x16 == 0x12:
            hosts[src].tcp.observe(False, dst, dport, sport, flags, seq, ack)
    return dst


def benchmark(folder, name, sensor=None):
    (pcap,) = folder.glob(name + "_pcap.pcap*")
    labels = folder / (name + "_labels.csv")
    minutes = {}
    reference = []
    hosts, targets = defaultdict(Host), set()
    first = last = onset = end = None
    ipv4 = positives = partial = 0

    def close(start):
        if len(reference) < 5:
            if targets or onset is not None:
                raise ValueError("reference minute must precede attack")
            reference.append({ip: h.metrics() for ip, h in hosts.items()})
        else:
            alerts, available = score(hosts, reference, start)
            minutes[start] = (alerts, available, targets.copy())

    from contextlib import closing

    source = (
        closing(sensor_packets(sensor, pcap)) if sensor else RawPcapReader(str(pcap))
    )
    with source as capture, labels.open(newline="") as stream:
        rows = csv.reader(stream)
        if next(rows) != ["", "x"]:
            raise ValueError("unexpected label header")
        for index, (record, row) in enumerate(zip_longest(capture, rows), 1):
            if (
                record is None
                or row is None
                or row[0] != str(index)
                or row[1] not in ("0", "1")
            ):
                raise ValueError(f"packet and label mismatch at {index}")
            if sensor:
                ts = int(record["timestamp_ns"]) / 1e9
            else:
                frame, meta = record
                if hasattr(meta, "tsresol"):
                    ts = ((meta.tshigh << 32) + meta.tslow) / meta.tsresol
                    link = meta.linktype
                else:
                    ts = meta.sec + meta.usec / (1e9 if capture.nano else 1e6)
                    link = capture.linktype
                if link != 1:
                    raise ValueError("expected Ethernet")
            if first is None:
                first = ts
                current = int(ts) // 60 * 60
                initial = current
            minute = int(ts) // 60 * 60
            if minute < current:
                raise ValueError("out-of-order minute")
            while current < minute:
                if current != initial:
                    close(current)
                hosts.clear()
                targets.clear()
                current += 60
            ip = (
                observe_metadata(hosts, record, ts)
                if sensor
                else observe(hosts, frame, ts)
            )
            ipv4 += ip is not None
            partial += (
                record["captured_length"] < record["wire_length"]
                if sensor
                else len(frame) < meta.wirelen
            )
            if row[1] == "1":
                onset = ts if onset is None else min(ts, onset)
                end = ts if end is None else max(ts, end)
                positives += 1
                if ip is not None:
                    targets.add(ip)
            last = ts
    if onset is None or not minutes:
        raise ValueError("no attack or complete test minutes")
    result = {}
    for label in RULES:
        expected = label in SCENARIOS[name]
        hits, exposed, false, relevant = [], 0, 0, 0
        previous_false = False
        previous_alerts = set()
        for start, (alerts, available, attack_ips) in sorted(minutes.items()):
            benign = start + 60 <= onset or start > end
            if benign and available[label]:
                exposed += 1
            this_false = bool(benign and alerts[label])
            false += this_false and not previous_false
            previous_false = this_false
            if expected and available[label] & attack_ips:
                relevant += 1
            if expected and (alerts[label] - previous_alerts) & attack_ips:
                hits.append(start + 60 - onset)
            previous_alerts = alerts[label]
        result[label] = dict(
            expected=expected,
            detected=bool(hits),
            assessed_attack_minutes=relevant,
            delay_s=round(min(hits), 3) if hits else None,
            false_incidents=false,
            assessed_benign_minutes=exposed,
        )
    return dict(
        name=name,
        packets=index,
        ipv4=ipv4,
        truncated_payload_or_frame=partial,
        labeled_packets=positives,
        first=first,
        last=last,
        onset=onset,
        end=end,
        full_test_minutes=len(minutes),
        pcap_sha256=sha(pcap),
        labels_sha256=sha(labels),
        rules=result,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    parser.add_argument("scenario", choices=SCENARIOS)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.folder, args.scenario), indent=2))
