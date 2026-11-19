"""Reduce a verified minute of Go packet metadata or a ModSecurity audit record."""

import argparse
import ipaddress
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import fmean, pstdev

from netwatch_ml.bursts import BurstRates
from netwatch_ml.handshakes import Handshakes
from netwatch_ml.security import assess, with_reference
from netwatch_ml.telemetry import combine, http_summary, observer, probe_summary


def _packet_minutes(lines, entity, start, minutes):
    target = ipaddress.ip_address(entity)
    lower = start * 1_000_000_000
    width = 60_000_000_000
    upper = lower + minutes * width
    port_bins = [defaultdict(set) for _ in range(minutes)]
    count_bins = [Counter() for _ in range(minutes)]
    bursts = [BurstRates() for _ in range(minutes)]
    handshakes = [Handshakes() for _ in range(minutes)]
    # Follow pending attempts for up to five seconds into the next interval.
    grace = 5_000_000_000
    boundary_attempts = [set() for _ in range(minutes)]
    for line in lines:
        packet = json.loads(line)
        stamp = int(packet["timestamp_ns"])
        if not lower <= stamp < upper + grace:
            continue
        if packet["decode_status"] == "non_ip":
            continue
        if packet["decode_status"] not in ("decoded", "fragment") and not (
            packet["decode_status"] == "truncated"
            and packet.get("header_complete") is True
        ):
            if stamp >= upper:
                continue
            raise ValueError("incomplete decoding in declared interval")
        index = (int(packet["timestamp_ns"]) - lower) // width
        if packet["decode_status"] == "fragment" and (
            not packet["dst_ip"] or not packet["src_ip"] or ":" in packet["src_ip"]
        ):
            raise ValueError("fragment lacks verified IPv4 transport protocol")
        inbound = ipaddress.ip_address(packet["dst_ip"]) == target
        if packet["protocol"] == "TCP" and (
            inbound or ipaddress.ip_address(packet["src_ip"]) == target
        ):
            peer_side, local_side = ("src", "dst") if inbound else ("dst", "src")
            args = (
                inbound,
                packet[peer_side + "_ip"],
                packet.get(peer_side + "_port"),
                packet.get(local_side + "_port"),
                packet.get("tcp_flags"),
                packet.get("tcp_seq"),
                packet.get("tcp_ack"),
            )
            flags, seq = args[-3:-1]
            flow = (args[1:4], seq)
            opening = flags is not None and inbound and flags & 0x16 == 2
            repeated = False
            previous = index - 1
            if previous >= 0 and stamp < lower + index * width + grace:
                prior = handshakes[previous]
                if not opening:
                    prior.observe(*args)
                elif flow in prior.attempts and flow not in prior.completed:
                    repeated = True
            if index < minutes and not repeated:
                handshakes[index].observe(*args)
                if opening and stamp + grace >= upper:
                    boundary_attempts[index].add(flow)
        if index >= minutes or not inbound:
            continue
        bursts[index].add((stamp - lower) // 1_000_000_000, packet["protocol"])
        count_bins[index][packet["protocol"]] += 1
        peer = port_bins[index][packet["src_ip"]]
        if packet["dst_port"] is not None:
            peer.add(packet["dst_port"])
    samples = []
    for counts, ports, tcp, burst, pending in zip(
        count_bins, port_bins, handshakes, bursts, boundary_attempts
    ):
        total = counts.total()
        metrics = dict(
            in_pps=total / 60,
            source_ips=len(ports),
            max_ports_one_peer=max((len(p) for p in ports.values()), default=0),
        )
        if total:
            metrics.update(
                udp_fraction=counts["UDP"] / total, icmp_fraction=counts["ICMP"] / total
            )
        metrics.update(tcp.metrics())
        censored = pending - tcp.completed
        if censored and "handshake_fraction" in metrics:
            metrics["handshake_fraction_upper"] = (
                len(tcp.completed) + len(censored)
            ) / len(tcp.attempts)
            metrics.pop("handshake_fraction")
        metrics.update(burst.metrics())
        samples.append(metrics)
    return samples


def packet_metrics(lines, entity, start):
    return _packet_minutes(lines, entity, start, 1)[0]


def from_packets(
    current, reference, entity, start, reference_start, reference_minutes=1
):
    if not 1 <= reference_minutes <= 60:
        raise ValueError("expected 1 to 60 verified reference minutes")
    if reference_start + reference_minutes * 60 > start:
        raise ValueError("the reference must precede the observed interval")
    current_metrics = packet_metrics(current, entity, start)
    samples = _packet_minutes(reference, entity, reference_start, reference_minutes)
    recent = with_reference(current_metrics, samples)
    return dict(
        schema_version=1, entity=entity, start_s=start, interval_s=60, metrics=recent
    )


def from_waf(record, entity, start):
    # The caller assigns the transaction to the entity/minute. Only CRS messages qualify.
    ids = set()
    for message in record["transaction"]["messages"]:
        details = message["details"]
        if any(
            (tag == "OWASP_CRS" or str(tag).startswith("OWASP_CRS/"))
            for tag in details.get("tags", [])
        ):
            rid = int(details["ruleId"])
            if 100000 <= rid <= 999999:
                ids.add(rid)
    return dict(
        schema_version=1,
        entity=entity,
        start_s=start,
        interval_s=60,
        metrics={},
        crs_rule_ids=sorted(ids),
    )


def from_events(lines, entity, start, kind, auth_history=False, history_minutes=1):
    """Aggregate a complete minute from one authenticator, DNS resolver or egress log."""
    if (
        history_minutes not in (1, 5, 15)
        or history_minutes != 1
        and kind not in ("dns", "egress")
    ):
        raise ValueError("DNS and egress history must be 1, 5 or 15 complete minutes")
    principals = defaultdict(Counter)
    history = defaultdict(Counter)
    horizons = (
        (1, 5, 15)
        if history_minutes == 15
        else (1, 5)
        if history_minutes == 5
        else (1,)
    )
    histories = {horizon: [] for horizon in horizons}
    policy = set()
    for line in lines:
        event = json.loads(line)
        ts = event["time_s"]
        lower = start - (
            240 if auth_history and kind == "auth" else (history_minutes - 1) * 60
        )
        if event["entity"] != entity or not lower <= ts < start + 60:
            continue
        if kind == "auth":
            if type(event["success"]) is not bool:
                raise ValueError("success must be a boolean")
            if auth_history:
                history[event["principal"]][event["success"]] += 1
            if ts >= start:
                principals[event["principal"]][event["success"]] += 1
        else:
            if type(event["unapproved_destination"]) is not bool:
                raise ValueError("destination policy must be explicit")
            policy.add(event["unapproved_destination"])
            if kind == "dns":
                label = event["qname"].rstrip(".").split(".")[0].lower()
                if not label or len(label) > 63:
                    raise ValueError("invalid DNS label")
                value = label
            else:
                value = ts
            for minutes in horizons:
                if ts >= start - (minutes - 1) * 60:
                    histories[minutes].append(value)
    metrics = {}
    if kind == "auth" and principals:

        def strongest(counts):
            return max(
                counts,
                key=lambda c: (
                    c[False] >= 10 and c[False] / c.total() >= 0.9,
                    c[False],
                    c[False] / c.total(),
                ),
            )

        counts = strongest(principals.values())
        metrics.update(
            auth_failures_same_principal=counts[False],
            auth_failure_fraction=counts[False] / counts.total(),
        )
        active = [
            history[p] for p, c in principals.items() if c[False] and p in history
        ]
        if active:
            counts = strongest(active)
            metrics.update(
                auth_failures_5m=counts[False],
                auth_failure_fraction_5m=counts[False] / counts.total(),
            )
    if len(policy) == 1:
        metrics["unapproved_destination"] = int(policy.pop())
    # Require activity in the current minute before reusing history.
    if histories[1]:
        for minutes, values in histories.items():
            suffix = "" if minutes == 1 else f"_{minutes}m"
            if kind == "dns":
                metrics.update(
                    {
                        "dns_queries" + suffix: len(values),
                        "dns_unique_label_fraction" + suffix: len(set(values))
                        / len(values),
                        "dns_mean_label_length" + suffix: fmean(map(len, values)),
                    }
                )
            elif len(values) >= 2:
                ordered = sorted(values)
                intervals = [b - a for a, b in zip(ordered, ordered[1:])]
                metrics["outbound_intervals" + suffix] = len(intervals)
                if fmean(intervals) > 0:
                    metrics["interval_cv" + suffix] = pstdev(intervals) / fmean(
                        intervals
                    )
    return dict(
        schema_version=1, entity=entity, start_s=start, interval_s=60, metrics=metrics
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--journal", help="Authenticated NetWatch API URL, e.g. http://127.0.0.1:8080"
    )
    parser.add_argument("--queue", action="store_true", help="submit a durable assessment job to the journal")
    sub = parser.add_subparsers(dest="kind", required=True)
    for kind in ("packets", "waf", "observation", "auth", "dns", "egress", "telemetry"):
        cmd = sub.add_parser(kind)
        cmd.add_argument("input", type=Path)
        if kind != "observation":
            cmd.add_argument("--entity", required=True)
            cmd.add_argument("--start", type=int, required=True)
        if kind in ("packets", "auth"):
            cmd.add_argument("--cohort", help="export a scoped observer record")
            cmd.add_argument("--policy-valid-until", type=int)
        if kind in ("auth", "dns", "egress"):
            cmd.add_argument("--complete-minute", action="store_true", required=True)
        if kind in ("dns", "egress"):
            cmd.add_argument(
                "--history-minutes",
                choices=(1, 5, 15),
                type=int,
                default=1,
                help="include verified continuous prior minutes in this observer log",
            )
        if kind == "auth":
            cmd.add_argument(
                "--auth-history",
                action="store_true",
                help="include the four preceding recorded minutes",
            )
        if kind == "packets":
            cmd.add_argument(
                "--destination", help="monitored IP when --entity names the service"
            )
            cmd.add_argument("--reference-minutes", type=int, default=1)
            cmd.add_argument("--reference", type=Path, required=True)
            cmd.add_argument("--reference-start", type=int, required=True)
            cmd.add_argument(
                "--complete-minutes",
                required=True,
                action="store_true",
                help="the operator verified full coverage of both 60-second intervals",
            )
    probe = sub.add_parser(
        "probe-log", help="produce a health observer record from a scheduled probe log"
    )
    probe.add_argument("input", type=Path)
    http = sub.add_parser(
        "http-log", help="produce an HTTP observer from normalized access logs"
    )
    http.add_argument("input", type=Path)
    args = parser.parse_args()
    if args.queue and not args.journal:
        parser.error("--queue requires --journal")
    cohort = getattr(args, "cohort", None)
    policy = getattr(args, "policy_valid_until", None)
    if (cohort is None) != (policy is None):
        parser.error("--cohort and --policy-valid-until are required together")
    if args.journal and (cohort is not None or args.kind in ("probe-log", "http-log")):
        parser.error("combine observer records with telemetry before journal delivery")
    with args.input.open() as stream:
        if args.kind == "probe-log":
            payload = json.load(stream)
            summary = probe_summary(
                payload["schedule"],
                payload["results"],
                payload["entity"],
                payload["start_s"],
                payload["cohort"],
                payload["policy_valid_until_s"],
            )
            print(json.dumps(summary, ensure_ascii=False))
            return
        if args.kind == "http-log":
            payload = json.load(stream)
            current = payload["current"]
            print(
                json.dumps(
                    http_summary(
                        current,
                        payload["references"],
                        current["entity"],
                        current["start_s"],
                        current["cohort"],
                        payload["policy_valid_until_s"],
                    ),
                    ensure_ascii=False,
                )
            )
            return
        if args.kind == "packets":
            with args.reference.open() as reference:
                observation = from_packets(
                    stream,
                    reference,
                    args.destination or args.entity,
                    args.start,
                    args.reference_start,
                    args.reference_minutes,
                )
        elif args.kind in ("auth", "dns", "egress"):
            observation = from_events(
                stream,
                args.entity,
                args.start,
                args.kind,
                getattr(args, "auth_history", False),
                getattr(args, "history_minutes", 1),
            )
        elif args.kind == "telemetry":
            observation = combine(
                (json.loads(line) for line in stream), args.entity, args.start
            )
        elif args.kind == "waf":
            observation = from_waf(json.load(stream), args.entity, args.start)
        else:
            observation = json.load(stream)
    if args.kind == "packets" and args.destination:
        observation["entity"] = args.entity
    if cohort is not None:
        source = "network" if args.kind == "packets" else "auth"
        record = observer(
            args.entity, args.start, cohort, source, observation["metrics"], policy
        )
        combine([record], args.entity, args.start)
        print(json.dumps(record, ensure_ascii=False))
        return
    if args.journal:
        import os
        from urllib.parse import urlsplit
        from urllib.request import HTTPRedirectHandler, Request, build_opener

        endpoint = urlsplit(args.journal)
        if (
            endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
            or not (
                endpoint.scheme == "https"
                and endpoint.hostname
                or endpoint.scheme == "http"
                and endpoint.hostname in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            parser.error("journal requires HTTPS or a loopback HTTP endpoint")
        token = os.getenv("NETWATCH_SENSOR_TOKEN")
        if not token:
            parser.error("NETWATCH_SENSOR_TOKEN is required")

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None

        route = "/v1/security/observations" if args.queue else "/v1/security/assess"
        req = Request(
            args.journal.rstrip("/") + route,
            data=json.dumps(observation).encode(),
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/json",
            },
        )
        with build_opener(NoRedirect).open(req, timeout=15) as response:
            result = json.load(response)
    else:
        result = assess(observation)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
