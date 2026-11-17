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
from netwatch_ml.security import RULES, assess

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
    syn: dict = field(default_factory=dict)
    replies: dict = field(default_factory=dict)
    complete: set = field(default_factory=set)

    def metrics(self):
        total = self.packets.total()
        data = dict(
            in_pps=total / 60,
            max_ports_one_peer=max(map(len, self.ports.values()), default=0),
            source_ips=len(self.ports),
            syn_per_second=len(self.syn) / 60,
        )
        if total:
            data.update(
                udp_fraction=self.packets[17] / total,
                icmp_fraction=self.packets[1] / total,
            )
        if self.syn:
            data["handshake_fraction"] = len(self.complete) / len(self.syn)
        return data


def observe(hosts, frame):
    # Kitsune truncates payloads. Only complete Ethernet/IPv4 and transport headers are used.
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    ihl = (frame[14] & 15) * 4
    if ihl < 20 or frame[14] >> 4 != 4 or len(frame) < 14 + ihl:
        raise ValueError("short IPv4 header")
    src, dst = frame[26:30], frame[30:34]
    proto = frame[23]
    host = hosts[dst]
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
        key = (src, sport, dport)
        if flags & 0x12 == 2:
            host.syn[(key, seq)] = True
        elif flags & 0x12 == 0x12:
            origin = hosts[src]
            attempt = ((dst, dport, sport), (ack - 1) % 2**32)
            if attempt in origin.syn:
                origin.replies[(attempt[0], (seq + 1) % 2**32)] = attempt
        elif flags & 0x10 and not flags & 4:
            attempt = host.replies.get((key, ack))
            if attempt is not None and seq == (attempt[1] + 1) % 2**32:
                host.complete.add(attempt)
    return dst


def score(hosts, reference, start):
    alerts, available = defaultdict(set), defaultdict(set)
    for ip in hosts.keys() | reference.keys():
        metrics = hosts[ip].metrics() if ip in hosts else Host().metrics()
        base = reference.get(ip, {})
        for metric, ratio in (
            ("in_pps", "pps_baseline_ratio"),
            ("max_ports_one_peer", "max_ports_baseline_ratio"),
            ("syn_per_second", "syn_rate_ratio"),
        ):
            if base.get(metric, 0) > 0:
                metrics[ratio] = metrics[metric] / base[metric]
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


def benchmark(folder, name):
    (pcap,) = folder.glob(name + "_pcap.pcap*")
    labels = folder / (name + "_labels.csv")
    minutes = {}
    reference = None
    hosts, targets = defaultdict(Host), set()
    first = last = onset = end = None
    ipv4 = positives = partial = 0

    def close(start):
        nonlocal reference
        if reference is None:
            if targets or onset is not None:
                raise ValueError("reference minute must precede attack")
            reference = {ip: h.metrics() for ip, h in hosts.items()}
        else:
            alerts, available = score(hosts, reference, start)
            minutes[start] = (alerts, available, targets.copy())

    with RawPcapReader(str(pcap)) as capture, labels.open(newline="") as stream:
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
            ip = observe(hosts, frame)
            ipv4 += ip is not None
            partial += len(frame) < meta.wirelen
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
