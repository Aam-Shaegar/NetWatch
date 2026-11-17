"""Classify passive observations from trusted sensors and security logs."""
from dataclasses import dataclass
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
    "port_scan": (Bound("max_ports_one_peer", 20), Bound("max_ports_baseline_ratio", 3)),
    "packet_flood": (Bound("in_pps", 100), Bound("pps_baseline_ratio", 5)),
    "dos": (Bound("pps_baseline_ratio", 5), Bound("unavailable_fraction", 0.3)),
    "ddos": (Bound("pps_baseline_ratio", 5), Bound("unavailable_fraction", 0.3), Bound("source_ips", 16)),
    "web_ddos": (Bound("http_rate_ratio", 5), Bound("http_error_fraction", 0.3), Bound("http_clients", 16)),
    "syn_flood": (Bound("syn_per_second", 20), Bound("syn_rate_ratio", 5), Bound("handshake_fraction", 0.2, True)),
    "udp_flood": (Bound("in_pps", 100), Bound("pps_baseline_ratio", 5), Bound("udp_fraction", 0.8)),
    "icmp_flood": (Bound("in_pps", 100), Bound("pps_baseline_ratio", 5), Bound("icmp_fraction", 0.8)),
    "slow_headers": (Bound("headers_pending", 20), Bound("oldest_header_seconds", 30), Bound("header_timeout_fraction", 0.5)),
    "possible_exfiltration": (Bound("sensitive_bytes_out", 65536), Bound("unapproved_destination", 1)),
    "password_guessing": (Bound("auth_failures_same_principal", 10), Bound("auth_failure_fraction", 0.9)),
    "possible_exploitation": (Bound("request_linked_process", 1), Bound("process_policy_violation", 1)),
    "source_spoofing": (Bound("invalid_ingress_source_packets", 3), Bound("ingress_policy_verified", 1)),
    "possible_mitm": (Bound("unapproved_gateway_mac_change", 1), Bound("tls_pin_mismatches", 1)),
    "dns_tunnel": (Bound("dns_queries", 30), Bound("dns_unique_label_fraction", 0.85),
                   Bound("dns_mean_label_length", 35), Bound("unapproved_destination", 1)),
    "possible_beacon": (Bound("outbound_intervals", 8), Bound("interval_cv", 0.08, True),
                        Bound("unapproved_destination", 1)),
}
WAF = {"xss": 941, "sqli": 942}
VALIDATOR = Draft202012Validator(json.loads((ROOT / "contracts/security-observation.schema.json").read_text()))


def assess(observation):
    VALIDATOR.validate(observation)
    json.dumps(observation, allow_nan=False)
    metrics = observation["metrics"]
    findings, unavailable = [], {}
    for label, bounds in RULES.items():
        missing = [b.metric for b in bounds if b.metric not in metrics]
        if missing:
            unavailable[label] = missing
        elif all(b.accepts(metrics[b.metric]) for b in bounds):
            findings.append({"label": label, "basis": "observed_pattern",
                             "evidence": {b.metric: metrics[b.metric] for b in bounds}})
    for label, prefix in WAF.items():
        if "crs_rule_ids" not in observation:
            unavailable[label] = ["crs_rule_ids"]
            continue
        hits = sorted({n for n in observation["crs_rule_ids"] if n // 1000 == prefix})
        if hits:
            findings.append({"label": label, "basis": "upstream_waf", "evidence": {"crs_rule_ids": hits}})
    evaluated = len(RULES) + len(WAF) - len(unavailable)
    return {"ruleset": "passive-v1", "entity": observation["entity"], "start_s": observation["start_s"],
            "interval_s": observation["interval_s"], "evaluated": evaluated, "findings": findings,
            "unassessed": unavailable}
