"""Score a single published Gotham device trace, keeping the capture vantage point fixed."""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
from functools import lru_cache
import ipaddress
import json
from pathlib import Path

from kitsune import Host, RULES, assess, sha

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


def evaluate(path):
    windows = defaultdict(lambda: defaultdict(Host))
    truth = defaultdict(lambda: defaultdict(set))
    first_label = {}
    with path.open(newline="") as stream:
        for row in csv.DictReader(stream):
            ts = timestamp(row["frame.time"])
            start = int(ts) // 60 * 60
            label = row["label"]
            dst = row["ip.dst"]
            src = row["ip.src"]
            if not dst or not src:
                continue
            host = windows[start][dst]
            proto = int(float(row["ip.proto"]))
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
    base_start = next(
        t
        for t in complete
        if datetime.fromtimestamp(t, timezone.utc).date() == NORMAL_DAY
        and set(truth[t]) == {"Benign"}
    )
    base = {ip: h.metrics() for ip, h in windows[base_start].items()}
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
        for ip, h in windows[t].items():
            metrics = h.metrics()
            # CSV lacks TCP sequence and ACK numbers; omit handshake-derived fields.
            metrics.pop("syn_per_second")
            for metric, ratio in (
                ("in_pps", "pps_baseline_ratio"),
                ("max_ports_one_peer", "max_ports_baseline_ratio"),
            ):
                if base.get(ip, {}).get(metric, 0) > 0:
                    metrics[ratio] = metrics[metric] / base[ip][metric]
            result = assess(
                dict(
                    schema_version=1,
                    entity=str(ipaddress.ip_address(ip)),
                    start_s=t,
                    interval_s=60,
                    metrics=metrics,
                )
            )
            for rule in RULES.keys() - result["unassessed"].keys():
                available[rule].add(ip)
            for item in result["findings"]:
                alerts[item["label"]].add(ip)
        for annotation, targets in truth[t].items():
            for rule in TYPES.get(annotation, []):
                ep = episodes[t // 86400, annotation, rule]
                ep["complete_minutes"] += 1
                ep["assessed"] |= bool(targets & available[rule])
                continuing = (
                    previous_alerts.get(rule, set())
                    if previous_minute == t - 60
                    else set()
                )
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
