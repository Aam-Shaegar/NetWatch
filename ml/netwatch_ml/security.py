"""Classify passive observations from trusted sensors and security logs."""

from dataclasses import dataclass
from statistics import median
import json
from pathlib import Path

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
    "web_ddos": (
        Bound("http_rate_ratio", 5),
        Bound("http_error_fraction", 0.3),
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


def assess(observation):
    VALIDATOR.validate(observation)
    json.dumps(observation, allow_nan=False)
    metrics = observation["metrics"]
    findings, unavailable = [], {}
    for label, bounds in RULES.items():
        checks = list(bounds)
        evidence = {}
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
                checks = [Bound(peak, 100)]
                above_ceiling = True
                evidence = {
                    k: metrics[k] for k in ("normal_" + peak, "normal_peak_pps_5s")
                }
        missing = [b.metric for b in checks if b.metric not in metrics]
        if missing:
            unavailable[label] = missing
        elif above_ceiling and all(b.accepts(metrics[b.metric]) for b in checks):
            evidence.update({b.metric: metrics[b.metric] for b in checks})
            findings.append(
                {"label": label, "basis": "observed_pattern", "evidence": evidence}
            )
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
    evaluated = len(RULES) + len(WAF) - len(unavailable)
    return {
        "ruleset": "passive-v2",
        "entity": observation["entity"],
        "start_s": observation["start_s"],
        "interval_s": observation["interval_s"],
        "evaluated": evaluated,
        "findings": findings,
        "unassessed": unavailable,
    }
