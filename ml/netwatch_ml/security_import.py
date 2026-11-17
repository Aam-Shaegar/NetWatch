"""Reduce a verified minute of Go packet metadata or a ModSecurity audit record."""
import argparse
from collections import defaultdict
import ipaddress
import json
from collections import Counter
from statistics import fmean, pstdev
from pathlib import Path

from netwatch_ml.security import assess


def packet_metrics(lines, entity, start):
    target = ipaddress.ip_address(entity)
    lower = start * 1_000_000_000
    upper = lower + 60_000_000_000
    ports = defaultdict(set)
    counts = defaultdict(int)
    total = 0
    for line in lines:
        packet = json.loads(line)
        if not lower <= int(packet["timestamp_ns"]) < upper:
            continue
        if packet["decode_status"] != "decoded":
            raise ValueError("incomplete decoding in declared interval")
        if ipaddress.ip_address(packet["dst_ip"]) != target:
            continue
        total += 1
        counts[packet["protocol"]] += 1
        peer = ports[packet["src_ip"]]
        if packet["dst_port"] is not None:
            peer.add(packet["dst_port"])
    metrics = dict(in_pps=total / 60, source_ips=len(ports),
                   max_ports_one_peer=max((len(p) for p in ports.values()), default=0))
    if total:
        metrics.update(udp_fraction=counts["UDP"]/total, icmp_fraction=counts["ICMP"]/total)
    return metrics


def from_packets(current, reference, entity, start, reference_start):
    recent = packet_metrics(current, entity, start)
    base = packet_metrics(reference, entity, reference_start)
    for value, ratio in (("in_pps", "pps_baseline_ratio"), ("max_ports_one_peer", "max_ports_baseline_ratio")):
        if base[value] > 0:
            recent[ratio] = recent[value] / base[value]
    return dict(schema_version=1, entity=entity, start_s=start, interval_s=60, metrics=recent)


def from_waf(record, entity, start):
    # The caller assigns the transaction to the entity/minute. Only CRS messages qualify.
    ids = set()
    for message in record["transaction"]["messages"]:
        details = message["details"]
        if any((tag == "OWASP_CRS" or str(tag).startswith("OWASP_CRS/")) for tag in details.get("tags", [])):
            rid = int(details["ruleId"])
            if 100000 <= rid <= 999999:
                ids.add(rid)
    return dict(schema_version=1, entity=entity, start_s=start, interval_s=60, metrics={}, crs_rule_ids=sorted(ids))


def from_events(lines, entity, start, kind):
    """Aggregate a complete minute from one authenticator, DNS resolver or egress log."""
    principals = defaultdict(Counter)
    labels, times, policy = [], [], set()
    for line in lines:
        event = json.loads(line)
        ts = event["time_s"]
        if event["entity"] != entity or not start <= ts < start + 60:
            continue
        if kind == "auth":
            if type(event["success"]) is not bool:
                raise ValueError("success must be a boolean")
            principals[event["principal"]][event["success"]] += 1
        else:
            if type(event["unapproved_destination"]) is not bool:
                raise ValueError("destination policy must be explicit")
            policy.add(event["unapproved_destination"])
            if kind == "dns":
                label = event["qname"].rstrip(".").split(".")[0].lower()
                if not label or len(label) > 63:
                    raise ValueError("invalid DNS label")
                labels.append(label)
            else:
                times.append(ts)
    metrics = {}
    if kind == "auth" and principals:
        counts = max(principals.values(), key=lambda c: (c[False], c[False]/c.total()))
        metrics.update(auth_failures_same_principal=counts[False], auth_failure_fraction=counts[False]/counts.total())
    if len(policy) == 1:
        metrics["unapproved_destination"] = int(policy.pop())
    if labels:
        metrics.update(dns_queries=len(labels), dns_unique_label_fraction=len(set(labels))/len(labels),
                       dns_mean_label_length=fmean(map(len, labels)))
    if len(times) >= 2:
        ordered = sorted(times)
        intervals = [b-a for a, b in zip(ordered, ordered[1:])]
        metrics["outbound_intervals"] = len(intervals)
        if fmean(intervals) > 0:
            metrics["interval_cv"] = pstdev(intervals)/fmean(intervals)
    return dict(schema_version=1, entity=entity, start_s=start, interval_s=60, metrics=metrics)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="kind", required=True)
    for kind in ("packets", "waf", "observation", "auth", "dns", "egress"):
        cmd = sub.add_parser(kind)
        cmd.add_argument("input", type=Path)
        if kind != "observation":
            cmd.add_argument("--entity", required=True)
            cmd.add_argument("--start", type=int, required=True)
        if kind in ("auth", "dns", "egress"):
            cmd.add_argument("--complete-minute", action="store_true", required=True)
        if kind == "packets":
            cmd.add_argument("--reference", type=Path, required=True)
            cmd.add_argument("--reference-start", type=int, required=True)
            cmd.add_argument("--complete-minutes", required=True, action="store_true",
                             help="the operator verified full coverage of both 60-second intervals")
    args = parser.parse_args()
    with args.input.open() as stream:
        if args.kind == "packets":
            with args.reference.open() as reference:
                observation = from_packets(stream, reference, args.entity, args.start, args.reference_start)
        elif args.kind in ("auth", "dns", "egress"):
            observation = from_events(stream, args.entity, args.start, args.kind)
        elif args.kind == "waf":
            observation = from_waf(json.load(stream), args.entity, args.start)
        else:
            observation = json.load(stream)
    print(json.dumps(assess(observation), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
