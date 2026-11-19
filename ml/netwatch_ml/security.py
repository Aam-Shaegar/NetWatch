"""Classify passive observations from trusted sensors and security logs."""

import json
from dataclasses import dataclass
from pathlib import Path
from statistics import median

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Bound:
    metric: str
    limit: float
    upper: bool = False

    def accepts(self, value):
        return value <= self.limit if self.upper else value >= self.limit


# Each rule is evaluated independently. An incident can have several indicators.
RULES = {
    "port_scan": (
        Bound("max_ports_one_peer", 20),
        Bound("max_ports_baseline_ratio", 3),
    ),
    "packet_flood": (Bound("in_pps", 100), Bound("pps_baseline_ratio", 5)),
    "dos": (Bound("pps_baseline_ratio", 5), Bound("unavailable_fraction", 0.3)),
    "ddos": (
        Bound("pps_baseline_ratio", 5),
        Bound("unavailable_fraction", 0.3),
        Bound("source_ips", 16),
    ),
    "http_load": (Bound("http_rate_ratio", 5),),
    "web_ddos": (
        Bound("http_rate_ratio", 5),
        Bound("http_error_fraction", 0.3),
        Bound("unavailable_fraction", 0.3),
        Bound("http_clients", 16),
    ),
    "syn_flood": (
        Bound("syn_per_second", 20),
        Bound("syn_rate_ratio", 5),
        Bound("handshake_fraction", 0.2, True),
    ),
    "udp_flood": (
        Bound("in_pps", 100),
        Bound("pps_baseline_ratio", 5),
        Bound("udp_fraction", 0.8),
    ),
    "icmp_flood": (
        Bound("in_pps", 100),
        Bound("pps_baseline_ratio", 5),
        Bound("icmp_fraction", 0.8),
    ),
    "slow_headers": (
        Bound("headers_pending", 20),
        Bound("oldest_header_seconds", 30),
        Bound("header_timeout_fraction", 0.5),
    ),
    "possible_exfiltration": (
        Bound("sensitive_bytes_out", 65536),
        Bound("unapproved_destination", 1),
    ),
    "password_guessing": (
        Bound("auth_failures_same_principal", 10),
        Bound("auth_failure_fraction", 0.9),
    ),
    "possible_exploitation": (
        Bound("request_linked_process", 1),
        Bound("process_policy_violation", 1),
    ),
    "source_spoofing": (
        Bound("invalid_ingress_source_packets", 3),
        Bound("ingress_policy_verified", 1),
    ),
    "possible_mitm": (
        Bound("unapproved_gateway_mac_change", 1),
        Bound("tls_pin_mismatches", 1),
    ),
    "dns_tunnel": (
        Bound("dns_queries", 30),
        Bound("dns_unique_label_fraction", 0.85),
        Bound("dns_mean_label_length", 35),
        Bound("unapproved_destination", 1),
    ),
    "possible_beacon": (
        Bound("outbound_intervals", 8),
        Bound("interval_cv", 0.08, True),
        Bound("unapproved_destination", 1),
    ),
}
CORRELATION_SOURCES = {
    "dos": {"network", "probe", "change"},
    "ddos": {"network", "probe", "change"},
    "web_ddos": {"http", "probe", "change"},
    "slow_headers": {"headers"},
    "possible_exfiltration": {"dlp"},
    "possible_exploitation": {"process"},
    "source_spoofing": {"ingress", "change"},
    "possible_mitm": {"gateway", "tls", "change"},
}
DEGRADATION_PATTERNS = {"dos", "ddos", "web_ddos"}
TRAFFIC_PATTERNS = {"packet_flood", "http_load", "syn_flood", "udp_flood", "icmp_flood"}
WAF = {"xss": 941, "sqli": 942}
VALIDATOR = Draft202012Validator(
    json.loads((ROOT / "contracts/security-observation.schema.json").read_text())
)


REFERENCE = {
    "in_pps": ("pps_baseline_ratio", "normal_pps_ceiling"),
    "max_ports_one_peer": ("max_ports_baseline_ratio", "normal_ports_ceiling"),
    "syn_per_second": ("syn_rate_ratio", "normal_syn_ceiling"),
}


BURST = {
    "packet_flood": "peak_pps_5s",
    "udp_flood": "peak_udp_pps_5s",
    "icmp_flood": "peak_icmp_pps_5s",
}


def normal_ceiling(values):
    center = median(values)
    mad = median(abs(v - center) for v in values)
    return center + max(center, 6 * mad)


def with_reference(metrics, samples):
    """Samples are complete normal minutes at the same interface for the same host."""
    result = dict(metrics)
    for metric, (ratio, ceiling) in REFERENCE.items():
        if (
            metric not in metrics
            or not samples
            or any(metric not in s for s in samples)
        ):
            continue
        values = [s[metric] for s in samples]
        center = median(values)
        if center > 0:
            result[ratio] = metrics[metric] / center
        if len(values) >= 5:
            result[ceiling] = normal_ceiling(values)
    for metric in BURST.values():
        if (
            metric in metrics
            and len(samples) >= 5
            and all(metric in s for s in samples)
        ):
            result["normal_" + metric] = normal_ceiling([s[metric] for s in samples])
    return result


# The absolute threshold and protocol-specific conditions still apply.
ADAPTIVE = {
    "packet_flood": "in_pps",
    "udp_flood": "in_pps",
    "icmp_flood": "in_pps",
    "port_scan": "max_ports_one_peer",
    "syn_flood": "syn_per_second",
}


def complete_observer(observation, source):
    observers = observation.get("correlation", {}).get("observers", {})
    metadata = observers.get(source, {})
    return metadata.get("coverage") == "complete"


def scheduled_change(observation):
    if not complete_observer(observation, "change"):
        return False
    change = observation["correlation"]["observers"]["change"]
    expiry = change["policy_valid_until_s"]
    return (
        change["expected_change"]
        and expiry is not None
        and expiry >= observation["start_s"] + observation["interval_s"]
    )


def correlation_status(observation, label):
    observers = observation.get("correlation", {}).get("observers", {})
    required = CORRELATION_SOURCES.get(label, set())
    if not required or not required <= observers.keys():
        return None
    relevant = [observers[source] for source in sorted(required)]
    if any(source["coverage"] != "complete" for source in relevant):
        return None
    end = observation["start_s"] + observation["interval_s"]
    if any(
        source["policy_valid_until_s"] is None or source["policy_valid_until_s"] < end
        for source in relevant
    ):
        return "stale_policy"
    if label in DEGRADATION_PATTERNS and scheduled_change(observation):
        return "expected_change"
    return "verified"


def assess(observation):
    VALIDATOR.validate(observation)
    json.dumps(observation, allow_nan=False)
    metrics = observation["metrics"]
    findings, unavailable = [], {}
    for label, bounds in RULES.items():
        context = correlation_status(observation, label)
        if (label in BURST or label in ("dos", "ddos")) and metrics.get("in_pps") == 0:
            # A measured zero packet count excludes even a subwindow burst.
            continue
        if label == "syn_flood" and metrics.get("syn_per_second") == 0:
            continue
        checks = list(bounds)
        evidence = {}
        basis = (
            "correlated_observation"
            if label in CORRELATION_SOURCES
            else "observed_pattern"
        )
        above_ceiling = True
        if label in ADAPTIVE:
            metric = ADAPTIVE[label]
            ratio, ceiling = REFERENCE[metric]
            if metric in metrics and ceiling in metrics:
                if metrics[metric] > metrics[ceiling] or ratio not in metrics:
                    checks = [b for b in checks if b.metric != ratio]
                    above_ceiling = metrics[metric] > metrics[ceiling]
                    evidence[ceiling] = metrics[ceiling]
        if label == "password_guessing":
            history = (
                Bound("auth_failures_5m", 10),
                Bound("auth_failure_fraction_5m", 0.9),
            )
            if all(
                b.metric in metrics and b.accepts(metrics[b.metric]) for b in history
            ):
                checks = history
        peak = BURST.get(label)
        if peak and {peak, "normal_" + peak, "normal_peak_pps_5s"} <= metrics.keys():
            ceiling = max(metrics["normal_" + peak], metrics["normal_peak_pps_5s"])
            if metrics[peak] >= 100 and metrics[peak] > ceiling:
                if metrics["normal_peak_pps_5s"] == 0:
                    basis = "burst_with_silent_reference"
                checks = [Bound(peak, 100)]
                above_ceiling = True
                evidence = {
                    k: metrics[k] for k in ("normal_" + peak, "normal_peak_pps_5s")
                }
        if label in ("dns_tunnel", "possible_beacon"):
            for suffix in ("_5m", "_15m"):
                longer = [
                    Bound(b.metric + suffix, b.limit, b.upper)
                    if b.metric != "unapproved_destination"
                    else b
                    for b in bounds
                ]
                if all(
                    b.metric in metrics and b.accepts(metrics[b.metric]) for b in longer
                ):
                    checks = longer
                    break
        if label == "syn_flood":
            upper = metrics.get("handshake_fraction_upper")
            if "handshake_fraction" not in metrics and upper is not None:
                # Only use a right-censored measurement when every possible
                # completion outcome would satisfy the existing rule.
                checks = [
                    Bound("handshake_fraction_upper", b.limit, b.upper)
                    if b.metric == "handshake_fraction" and b.accepts(upper)
                    else b
                    for b in checks
                ]
        missing = [b.metric for b in checks if b.metric not in metrics]
        if label in CORRELATION_SOURCES:
            if not above_ceiling or any(
                b.metric in metrics and not b.accepts(metrics[b.metric]) for b in checks
            ):
                continue
            if context not in {"verified", "expected_change"}:
                missing.append(
                    "policy_freshness"
                    if context == "stale_policy"
                    else "fresh_correlated_telemetry"
                )
        if missing:
            unavailable[label] = missing
        elif (
            context != "expected_change"
            and above_ceiling
            and all(b.accepts(metrics[b.metric]) for b in checks)
        ):
            evidence.update({b.metric: metrics[b.metric] for b in checks})
            findings.append({"label": label, "basis": basis, "evidence": evidence})
    for label, prefix in WAF.items():
        if "crs_rule_ids" not in observation:
            unavailable[label] = ["crs_rule_ids"]
            continue
        hits = sorted({n for n in observation["crs_rule_ids"] if n // 1000 == prefix})
        if hits:
            findings.append(
                {
                    "label": label,
                    "basis": "upstream_waf",
                    "evidence": {"crs_rule_ids": hits},
                }
            )
    for item in findings:
        if item["basis"] == "upstream_waf":
            item["kind"] = "waf_signal"
        elif item["label"] in DEGRADATION_PATTERNS:
            item["kind"] = "degradation_pattern"
        elif item["label"] in TRAFFIC_PATTERNS:
            item["kind"] = "traffic_pattern"
        else:
            item["kind"] = "security_indicator"
    unavailable_fraction = metrics.get("unavailable_fraction")
    if not complete_observer(observation, "probe") or unavailable_fraction is None:
        availability = "unmeasured"
    else:
        availability = "degraded" if unavailable_fraction > 0 else "reachable"
    evaluated = len(RULES) + len(WAF) - len(unavailable)
    return {
        "ruleset": "passive-v5",
        "entity": observation["entity"],
        "start_s": observation["start_s"],
        "interval_s": observation["interval_s"],
        "evaluated": evaluated,
        "availability": availability,
        "scheduled_change": scheduled_change(observation),
        "findings": findings,
        "unassessed": unavailable,
    }
