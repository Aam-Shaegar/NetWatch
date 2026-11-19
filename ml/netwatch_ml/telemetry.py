"""Join trusted minute summaries with evidence from the same observation scope."""

from itertools import pairwise
from statistics import median

from netwatch_ml.security import BURST, REFERENCE, VALIDATOR

SOURCE_METRICS = {
    "network": (
        {
            "source_ips",
            "handshake_fraction",
            "handshake_fraction_upper",
            "udp_fraction",
            "icmp_fraction",
        }
        | {key for metric, names in REFERENCE.items() for key in (metric, *names)}
        | {key for metric in BURST.values() for key in (metric, "normal_" + metric)}
    ),
    "auth": {
        "auth_failures_same_principal",
        "auth_failure_fraction",
        "auth_failures_5m",
        "auth_failure_fraction_5m",
    },
    "probe": {"unavailable_fraction"},
    "http": {"http_rate_ratio", "http_error_fraction", "http_clients"},
    "headers": {"headers_pending", "oldest_header_seconds", "header_timeout_fraction"},
    "dlp": {"sensitive_bytes_out", "unapproved_destination"},
    "process": {"request_linked_process", "process_policy_violation"},
    "ingress": {"invalid_ingress_source_packets", "ingress_policy_verified"},
    "gateway": {"unapproved_gateway_mac_change"},
    "tls": {"tls_pin_mismatches"},
    "change": set(),
}


def combine(records, entity, start):
    """Group authenticated observer summaries by entity, minute and correlation ID."""
    metrics, sources, cohort = {}, {}, None
    for record in records:
        if set(record) != {
            "entity",
            "start_s",
            "cohort",
            "source",
            "coverage",
            "expected_change",
            "policy_valid_until_s",
            "metrics",
        }:
            raise ValueError("invalid observer fields")
        if record["entity"] != entity or record["start_s"] != start:
            raise ValueError("observer is outside the requested scope")
        source = record["source"]
        if source not in SOURCE_METRICS or source in sources:
            raise ValueError("unknown or duplicate observer")
        if not isinstance(record["cohort"], str) or not record["cohort"]:
            raise ValueError("missing observation cohort")
        if cohort is not None and record["cohort"] != cohort:
            raise ValueError("observers describe different cohorts")
        cohort = record["cohort"]
        if (
            set(record["metrics"]) - SOURCE_METRICS[source]
            or record["coverage"] not in ("complete", "partial", "missing")
            or type(record["expected_change"]) is not bool
            or (record["expected_change"] and source != "change")
        ):
            raise ValueError("invalid observer metrics, coverage or change state")
        sources[source] = record
        if record["coverage"] == "complete":
            metrics.update(record["metrics"])

    observation = dict(
        schema_version=1, entity=entity, start_s=start, interval_s=60, metrics=metrics
    )
    if sources:
        observation["correlation"] = {
            "cohort": cohort,
            "observers": {
                key: {
                    field: record[field]
                    for field in ("coverage", "expected_change", "policy_valid_until_s")
                }
                for key, record in sources.items()
            },
        }
    VALIDATOR.validate(observation)
    return observation


def probe_summary(schedule, results, entity, start, cohort, policy_valid_until_s):
    """Build a probe observer record using an explicit schedule and recorded outcomes."""
    expected = {}
    for slot in schedule:
        identity, stamp = slot["id"], slot["time_s"]
        if not isinstance(identity, str) or not identity or identity in expected:
            raise ValueError("missing or duplicate scheduled probe ID")
        if type(stamp) not in (int, float) or not start <= stamp < start + 60:
            raise ValueError("scheduled probe is outside the interval")
        expected[identity] = stamp
    if not expected:
        raise ValueError("empty probe schedule")

    completed = {}
    for result in results:
        identity = result["id"]
        if (
            result["entity"] != entity
            or result["cohort"] != cohort
            or identity not in expected
            or identity in completed
        ):
            raise ValueError("probe result does not match the schedule and scope")
        timestamp = result["time_s"]
        if (
            type(timestamp) not in (int, float)
            or not expected[identity] <= timestamp < start + 60
            or type(result["available"]) is not bool
        ):
            raise ValueError("invalid probe result time or outcome")
        completed[identity] = result["available"]

    complete = completed.keys() == expected.keys()
    metrics = (
        {
            "unavailable_fraction": sum(not ok for ok in completed.values())
            / len(expected)
        }
        if complete
        else {}
    )
    return observer(
        entity, start, cohort, "probe", metrics, policy_valid_until_s, complete
    )


def observer(
    entity, start, cohort, source, metrics, policy_valid_until_s, complete=True
):
    return {
        "entity": entity,
        "start_s": start,
        "cohort": cohort,
        "source": source,
        "coverage": "complete" if complete else "partial",
        "expected_change": False,
        "policy_valid_until_s": policy_valid_until_s,
        "metrics": metrics if complete else {},
    }


def http_summary(current, references, entity, start, cohort, policy_valid_until_s):
    """Reduce final HTTP statuses from complete, same-scope access-log windows."""

    def window(record):
        if (
            record["entity"] != entity
            or record["cohort"] != cohort
            or type(record["start_s"]) is not int
            or record["start_s"] < 0
            or type(record["complete"]) is not bool
        ):
            raise ValueError("HTTP log does not match the observation scope")
        requests = {}
        for event in record["events"]:
            identity, client, stamp, status = (
                event[key] for key in ("id", "client", "time_s", "status")
            )
            if (
                not isinstance(identity, str)
                or not identity
                or identity in requests
                or not isinstance(client, str)
                or not client
                or type(stamp) not in (int, float)
                or not record["start_s"] <= stamp < record["start_s"] + 60
                or type(status) is not int
                or not 200 <= status <= 599
            ):
                raise ValueError("invalid or duplicate HTTP access-log entry")
            requests[identity] = (client, status)
        return list(requests.values())

    if current["start_s"] != start:
        raise ValueError("HTTP log is outside the requested minute")
    entries = window(current)
    reference_starts, ordinary = set(), []
    for record in references:
        seen = window(record)
        reference_start = record["start_s"]
        if (
            reference_start + 60 > start
            or reference_start in reference_starts
            or not record["complete"]
        ):
            raise ValueError(
                "HTTP reference must be a distinct, earlier complete minute"
            )
        reference_starts.add(reference_start)
        ordinary.append(len(seen))
    ordered = sorted(reference_starts)
    if any(a + 60 > b for a, b in pairwise(ordered)):
        raise ValueError("HTTP reference windows overlap")

    metrics = {"http_clients": len({client for client, _ in entries})}
    if entries:
        metrics["http_error_fraction"] = sum(
            status >= 500 for _, status in entries
        ) / len(entries)
    if ordinary and (baseline := median(ordinary)) > 0:
        metrics["http_rate_ratio"] = len(entries) / baseline
    return observer(
        entity,
        start,
        cohort,
        "http",
        metrics,
        policy_valid_until_s,
        current["complete"],
    )
