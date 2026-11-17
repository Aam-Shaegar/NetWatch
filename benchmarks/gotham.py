"""Score a single published Gotham device trace, keeping the capture vantage point fixed."""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import json
from pathlib import Path

from scapy.utils import RawPcapReader
import socket
from kitsune import observe, Host, RULES, assess, sha, with_reference

# Windows are UTC aligned. First day of these traces is the authors' normal experiment.
NORMAL_DAY = datetime(2025, 1, 14, tzinfo=timezone.utc).date()
TYPES = {
    "TCP Scan": ["port_scan"],
    "Telnet Brute Force": ["password_guessing"],
    "C&C Communication": ["possible_beacon"],
    "CoAP Amplification": ["packet_flood", "udp_flood", "dos"],
    "DoS": ["packet_flood", "dos"],
    "UDP Scan": ["port_scan"],
    "Merlin ICMP Flooding": ["packet_flood", "icmp_flood"],
    "Merlin TCP Flooding": ["packet_flood"],
    "Merlin UDP Flooding": ["packet_flood", "udp_flood"],
    "Mirai UDP Flooding": ["packet_flood", "udp_flood"],
    "Mirai TCP Flooding": ["packet_flood"],
    "Mirai GRE Flooding": ["packet_flood"],
    "Merlin C&C Communication": ["possible_beacon"],
    "Mirai C&C Communication": ["possible_beacon"],
}


@lru_cache(maxsize=64)
def date_seconds(date):
    return datetime.strptime(date, "%b %d, %Y").replace(tzinfo=timezone.utc).timestamp()


def timestamp(value):
    day, clock, zone = value.rsplit(" ", 2)
    if zone != "GMT":
        raise ValueError("expected GMT")
    return (
        date_seconds(day)
        + int(clock[:2]) * 3600
        + int(clock[3:5]) * 60
        + float(clock[6:])
    )


RAW = {
    "iotsim-combined-cycle-1.csv": "iotsim-combined-cycle-1_0-0_to_OpenvSwitch-13_1-0.pcap",
    "iotsim-combined-cycle-10.csv": "iotsim-combined-cycle-10_0-0_to_OpenvSwitch-13_10-0.pcap",
}


def capture_minutes(path, label_keys=None):
    """Bound full minutes by the capture clock; match labelled IPv4 records by wire identity."""
    windows = defaultdict(lambda: defaultdict(Host))
    first = last = None
    with RawPcapReader(str(path)) as reader:
        if reader.linktype != 1 or reader.nano:
            raise ValueError("expected microsecond Ethernet PCAP")
        for frame, meta in reader:
            ts_us = meta.sec * 1_000_000 + meta.usec
            minute = meta.sec // 60 * 60
            if first is None:
                first = minute
            if last is not None and minute < last:
                raise ValueError("capture minutes out of order")
            last = minute
            dst = observe(windows[minute], frame, meta.sec)
            if label_keys is not None and dst is not None:
                key = (
                    ts_us,
                    socket.inet_ntoa(frame[26:30]),
                    socket.inet_ntoa(dst),
                    meta.wirelen,
                )
                if label_keys.get(key, 0):
                    label_keys[key] -= 1
    if first is None or last - first < 120:
        raise ValueError("capture has no complete minute")
    if label_keys is not None and any(label_keys.values()):
        raise ValueError("labelled CoAP packets do not align with the raw capture")
    return {
        t: {socket.inet_ntoa(ip): h for ip, h in windows[t].items()}
        for t in range(first + 60, last, 60)
    }


def evaluate(path):
    windows = defaultdict(lambda: defaultdict(Host))
    truth = defaultdict(lambda: defaultdict(set))
    first_label = {}
    coap_keys = Counter()
    with path.open(newline="") as stream:
        for row in csv.DictReader(stream):
            ts = timestamp(row["frame.time"])
            start = int(ts) // 60 * 60
            label = row["label"]
            dst = row["ip.dst"]
            src = row["ip.src"]
            if not dst or not src:
                continue
            if label == "CoAP Amplification":
                coap_keys[round(ts * 1_000_000), src, dst, int(row["frame.len"])] += 1
            host = windows[start][dst]
            proto = int(float(row["ip.proto"]))
            host.burst.add(ts, {17: "UDP", 1: "ICMP"}.get(proto))
            host.packets[proto] += 1
            ports = host.ports[src]
            value = row["tcp.dstport"] or row["udp.dstport"]
            if value:
                ports.add(int(float(value)))
            truth[start][label].add(dst)
            key = (start // 86400, label)
            first_label[key] = min(first_label.get(key, ts), ts)
    # Adjacent occupied minutes bound observation on both sides, even across concatenated captures.
    complete = sorted(t for t in windows if t - 60 in windows and t + 60 in windows)
    baseline_minutes = sorted(
        t
        for t in complete
        if datetime.fromtimestamp(t, timezone.utc).date() == NORMAL_DAY
        and set(truth[t]) == {"Benign"}
    )
    baseline_minutes = baseline_minutes[:5]
    if path.name in RAW:
        benign = capture_minutes(path.with_name(RAW[path.name]))
        baseline_minutes = sorted(benign)[:5]
        calibration = benign
    else:
        calibration = windows
    if not baseline_minutes:
        raise ValueError("no covered calibration minutes")
    base_start = baseline_minutes[-1]
    reference = [
        {ip: h.metrics() for ip, h in calibration[t].items()} for t in baseline_minutes
    ]
    if coap_keys:
        raw = capture_minutes(path.with_name("coap-" + RAW[path.name]), coap_keys)
        # Use the raw measurements only in windows bearing this capture's verified labels.
        verified = {t for t in raw if "CoAP Amplification" in truth.get(t, {})}
        complete = sorted(set(complete) | verified)
        for t in verified:
            windows[t] = raw[t]
    labels = sorted({l for _, l in first_label})
    episodes = {
        (day, annotation, rule): dict(
            onset=ts, matched=False, assessed=False, complete_minutes=0, delay_s=None
        )
        for (day, annotation), ts in first_label.items()
        for rule in TYPES.get(annotation, [])
    }
    fp, exposure, last_false = Counter(), Counter(), {}
    previous_alerts, previous_minute = {}, None
    for t in complete:
        if t <= base_start:
            continue
        available, alerts = defaultdict(set), defaultdict(set)
        measurements = {}
        for ip, h in windows[t].items():
            metrics = h.metrics()
            # CSV lacks TCP sequence and ACK numbers; omit handshake-derived fields.
            metrics.pop("syn_per_second")
            empty = Host().metrics()
            metrics = with_reference(
                metrics, [minute.get(ip, empty) for minute in reference]
            )
            result = assess(
                dict(
                    schema_version=1,
                    entity=str(ipaddress.ip_address(ip)),
                    start_s=t,
                    interval_s=60,
                    metrics=metrics,
                )
            )
            measurements[ip] = (metrics, result["unassessed"])
            for rule in RULES.keys() - result["unassessed"].keys():
                available[rule].add(ip)
            for item in result["findings"]:
                alerts[item["label"]].add(ip)
        for annotation, targets in truth[t].items():
            for rule in TYPES.get(annotation, []):
                ep = episodes[t // 86400, annotation, rule]
                ep["complete_minutes"] += 1
                for target in targets:
                    values, missing = measurements[target]
                    for metric in (
                        "in_pps",
                        "peak_pps_5s",
                        "peak_udp_pps_5s",
                        "peak_icmp_pps_5s",
                        "max_ports_one_peer",
                    ):
                        maxima = ep.setdefault("observed_max", {})
                        maxima[metric] = max(
                            maxima.get(metric, 0), values.get(metric, 0)
                        )
                    if rule in missing:
                        ep["missing_metrics"] = sorted(
                            set(ep.get("missing_metrics", [])) | set(missing[rule])
                        )
                ep["assessed"] |= bool(targets & available[rule])
                continuing = (
                    previous_alerts.get(rule, set())
                    if previous_minute == t - 60
                    else set()
                )
                if targets & alerts[rule]:
                    ep["active_minutes"] = ep.get("active_minutes", 0) + 1
                if targets & (alerts[rule] - continuing) and not ep["matched"]:
                    ep.update(matched=True, delay_s=round(t + 60 - ep["onset"], 3))
        previous_alerts, previous_minute = alerts, t
        if set(truth[t]) == {"Benign"}:
            for rule in available:
                exposure[rule] += 1
                if alerts[rule]:
                    fp[rule] += last_false.get(rule) != t - 60
                    last_false[rule] = t
    return dict(
        file=path.name,
        sha256=sha(path),
        baseline=base_start,
        reference_minutes=len(reference),
        labels=labels,
        episodes=[
            dict(day=day, annotation=anno, rule=rule, **ep)
            for (day, anno, rule), ep in sorted(episodes.items())
        ],
        normal={r: dict(minutes=n, false_incidents=fp[r]) for r, n in exposure.items()},
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    print(json.dumps(evaluate(parser.parse_args().file), indent=2))
