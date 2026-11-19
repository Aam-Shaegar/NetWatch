from fastapi.testclient import TestClient
from netwatch_ml.serving.app import create_app
from netwatch_ml.security_import import from_waf


def test_missing_service_health_does_not_confirm_ddos():
    client = TestClient(create_app())
    obs = dict(
        schema_version=1,
        entity="test",
        start_s=0,
        interval_s=60,
        metrics=dict(in_pps=150, pps_baseline_ratio=6, source_ips=20),
    )

    def get():
        response = client.post("/v1/security/assess", json=obs)
        assert response.status_code == 200
        return response.json()

    first = get()
    assert [f["label"] for f in first["findings"]] == ["packet_flood"]
    assert "unavailable_fraction" in first["unassessed"]["ddos"]
    obs["metrics"]["unavailable_fraction"] = 0.4
    assert "fresh_correlated_telemetry" in get()["unassessed"]["ddos"]
    observer = dict(coverage="complete", expected_change=False, policy_valid_until_s=60)
    obs["correlation"] = dict(
        cohort="site-v1",
        observers={key: dict(observer) for key in ("network", "probe", "change")},
    )
    assert {f["label"] for f in get()["findings"]} == {"dos", "ddos", "packet_flood"}
    obs["correlation"]["observers"]["change"]["expected_change"] = True
    assert {f["label"] for f in get()["findings"]} == {"packet_flood"}
    obs["correlation"]["observers"]["change"]["policy_valid_until_s"] = 59
    assert "policy_freshness" in get()["unassessed"]["ddos"]
    obs["metrics"]["unavailable_fraction"] = 1.3
    assert client.post("/v1/security/assess", json=obs).status_code == 422


def test_unrelated_ruleset_does_not_become_a_crs_finding():
    msg = {"details": {"ruleId": "942100", "tags": ["local"]}}
    record = {"transaction": {"messages": [msg]}}
    assert from_waf(record, "lab", 0)["crs_rule_ids"] == []
    msg["details"]["tags"] = ["OWASP_CRS"]
    assert from_waf(record, "lab", 0)["crs_rule_ids"] == [942100]


def test_events_keep_accounts_and_time_windows_separate():
    import json
    from netwatch_ml.security_import import from_events
    from netwatch_ml.security import assess

    rows = [
        dict(entity="service", time_s=i, principal=str(i % 2), success=False)
        for i in range(20)
    ]

    def findings(events):
        obs = from_events(map(json.dumps, events), "service", 0, "auth")
        return [item["label"] for item in assess(obs)["findings"]]

    assert findings(rows) == ["password_guessing"]
    assert findings(rows[:18] + [dict(rows[0], time_s=60)]) == []


def test_periodicity_needs_consistent_destination_policy():
    import json
    from netwatch_ml.security_import import from_events
    from netwatch_ml.security import assess

    rows = [
        dict(entity="service:peer", time_s=i * 5, unapproved_destination=True)
        for i in range(10)
    ]

    def observation():
        return from_events(map(json.dumps, rows), "service:peer", 0, "egress")

    assert assess(observation())["findings"][0]["label"] == "possible_beacon"
    rows[-1]["unapproved_destination"] = False
    assert "possible_beacon" in assess(observation())["unassessed"]


def test_verified_quiet_history_and_missing_reference_are_distinct():
    from netwatch_ml.security import assess, with_reference

    obs = dict(schema_version=1, entity="service", start_s=300, interval_s=60)
    stats = {"max_ports_one_peer": 25}

    def result(samples):
        return assess(dict(obs, metrics=with_reference(stats, samples)))

    assert "port_scan" in result([{}] * 5)["unassessed"]
    assert "port_scan" in result([{"max_ports_one_peer": 0}] * 4)["unassessed"]
    (finding,) = result([{"max_ports_one_peer": 0}] * 5)["findings"]
    assert finding["label"] == "port_scan"
    assert finding["evidence"]["normal_ports_ceiling"] == 0


def test_udp_burst_needs_protocol_dominance_in_the_same_bin():
    from netwatch_ml.bursts import BurstRates
    from netwatch_ml.security import assess, with_reference

    def check(n_udp):
        burst = BurstRates()
        for i in range(600):
            burst.add(5, "UDP" if i < n_udp else "TCP")
        baseline = BurstRates()
        baseline.add(5, "UDP")
        normal = baseline.metrics()
        return {
            f["label"]
            for f in assess(
                dict(
                    schema_version=1,
                    entity="service",
                    start_s=0,
                    interval_s=60,
                    metrics=with_reference(burst.metrics(), [normal] * 5),
                )
            )["findings"]
        }

    assert check(500) == {"packet_flood", "udp_flood"}
    assert check(400) == {"packet_flood"}


def test_repeated_auth_failures_need_recent_evidence_and_one_account():
    import json
    from netwatch_ml.security import assess
    from netwatch_ml.security_import import from_events

    def detected(times, principals):
        lines = (
            json.dumps(dict(time_s=t, entity="auth", principal=p, success=False))
            for t, p in zip(times, principals)
        )
        obs = from_events(lines, "auth", 840, "auth", auth_history=True)
        return bool(assess(obs)["findings"])

    times = [610] * 3 + [670] * 3 + [850] * 4
    assert detected(times, ["u"] * 10)
    assert not detected(times, ["x", "y"] * 5)
    assert not detected([100] * 3 + [400] * 3 + [650] * 4, ["u"] * 10)


def test_handshake_retries_do_not_inflate_attempts():
    from netwatch_ml.handshakes import Handshakes

    tcp = Handshakes()

    def event(inbound, flags, seq, ack):
        tcp.observe(inbound, "peer", 41000, 8080, flags, seq, ack)

    event(True, 2, 100, 0)
    event(True, 2, 100, 0)
    event(False, 18, 200, 101)
    event(True, 16, 101, 201)
    assert tcp.metrics() == {"syn_per_second": 1 / 60, "handshake_fraction": 1}


def test_packet_import_applies_history_before_assessing_burst():
    import json
    from netwatch_ml.security_import import from_packets
    from netwatch_ml.security import assess

    record = dict(
        timestamp_ns="305000000000",
        src_ip="192.0.2.2",
        dst_ip="192.0.2.1",
        dst_port=5000,
        protocol="UDP",
        decode_status="decoded",
    )
    source = [json.dumps(record)] * 550
    quiet = from_packets(source, [], "192.0.2.1", 300, 0, 5)
    assert all(
        f["basis"] == "burst_with_silent_reference" for f in assess(quiet)["findings"]
    )
    reference = [
        json.dumps(dict(record, timestamp_ns=str((minute * 60 + 1) * 10**9)))
        for minute in range(5)
    ]
    observation = from_packets(source, reference, "192.0.2.1", 300, 0, 5)
    assert observation["metrics"]["peak_udp_pps_5s"] == 110
    assert {f["label"] for f in assess(observation)["findings"]} == {
        "packet_flood",
        "udp_flood",
    }


def test_minute_boundary_and_censored_handshake():
    import json
    from netwatch_ml.security_import import packet_metrics

    def record(second, inbound, flags, seq, ack):
        endpoints = ("192.0.2.1", "192.0.2.2", 41000, 8080)
        src, dst, sport, dport = endpoints
        if not inbound:
            src, dst, sport, dport = dst, src, dport, sport
        return json.dumps(
            dict(
                timestamp_ns=str(second * 10**9),
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                protocol="TCP",
                decode_status="decoded",
                tcp_flags=flags,
                tcp_seq=seq,
                tcp_ack=ack,
            )
        )

    packets = [
        record(59, True, 2, 9, 0),
        record(60, False, 18, 20, 10),
        record(61, True, 16, 10, 21),
    ]
    assert packet_metrics(packets, "192.0.2.2", 0)["handshake_fraction"] == 1
    assert "handshake_fraction" not in packet_metrics(packets[:1], "192.0.2.2", 0)
    assert packet_metrics(packets[:1], "192.0.2.2", 0)["handshake_fraction_upper"] == 1

    assert packet_metrics(packets, "192.0.2.2", 0)["in_pps"] == 1 / 60


def test_shifted_packet_interval_separates_first_and_last_seconds():
    import json
    from netwatch_ml.security_import import packet_metrics

    def record(second):
        return json.dumps(
            dict(
                timestamp_ns=str(second * 10**9),
                src_ip="192.0.2.1",
                dst_ip="192.0.2.2",
                dst_port=8080,
                protocol="UDP",
                decode_status="decoded",
            )
        )

    for start in (0, 2, 59):
        packets = [record(start)] * 50 + [record(start + 59)] * 50
        assert packet_metrics(packets, "192.0.2.2", start)["peak_pps_5s"] == 10


def test_export_requires_same_minute_and_cohort():
    import pytest
    from netwatch_ml.telemetry import combine

    base = dict(
        entity="https-service",
        start_s=0,
        cohort="scope-1",
        coverage="complete",
        expected_change=False,
        policy_valid_until_s=60,
    )
    network = dict(
        base, source="network", metrics={"source_ips": 18, "pps_baseline_ratio": 10}
    )
    probe = dict(base, source="probe", metrics={"unavailable_fraction": 0.5})
    change = dict(base, source="change", metrics={})
    assert (
        combine([network, probe, change], "https-service", 0)["correlation"]["cohort"]
        == "scope-1"
    )
    with pytest.raises(ValueError, match="cohorts"):
        combine([network, dict(probe, cohort="other")], "https-service", 0)
    with pytest.raises(ValueError, match="scope"):
        combine([network, dict(probe, start_s=60)], "https-service", 0)


def test_history_keeps_sparse_periodic_evidence_within_the_same_scope():
    import json
    from netwatch_ml.security import assess
    from netwatch_ml.security_import import from_events

    rows = [
        dict(entity="service:peer", time_s=timestamp, unapproved_destination=True)
        for timestamp in range(10, 300, 28)
    ]
    one = from_events(map(json.dumps, rows), "service:peer", 240, "egress")
    assert assess(one)["findings"] == []
    history = from_events(
        map(json.dumps, rows), "service:peer", 240, "egress", history_minutes=5
    )
    findings = assess(history)["findings"]
    assert "outbound_intervals_5m" in findings[0]["evidence"]


def test_censored_syn_is_reported_only_when_upper_bound_is_conclusive():
    from netwatch_ml.security import assess

    obs = dict(
        schema_version=1,
        entity="service",
        start_s=0,
        interval_s=60,
        metrics=dict(
            syn_per_second=30, syn_rate_ratio=10, handshake_fraction_upper=0.1
        ),
    )
    signal = next(row for row in assess(obs)["findings"] if row["label"] == "syn_flood")
    assert signal["evidence"]["handshake_fraction_upper"] == 0.1
    obs["metrics"]["handshake_fraction_upper"] = 0.6
    assert "syn_flood" in assess(obs)["unassessed"]


def test_confirmed_silence_excludes_traffic_pressure_without_fabricating_probe_results():
    from netwatch_ml.security import assess

    obs = dict(
        schema_version=1,
        entity="service",
        start_s=0,
        interval_s=60,
        metrics={"in_pps": 0},
    )
    result = assess(obs)
    assert not ({"dos", "ddos"} & result["unassessed"].keys())
    assert not result["findings"]
    obs["metrics"].clear()
    assert {"dos", "ddos"} <= assess(obs)["unassessed"].keys()


def test_probe_coverage_requires_one_outcome_per_scheduled_sample():
    import pytest
    from netwatch_ml.telemetry import probe_summary

    schedule = [dict(id="opening", time_s=1), dict(id="closing", time_s=30)]
    good = dict(
        id="opening", time_s=1.2, entity="service", cohort="site", available=True
    )
    bad = dict(
        id="closing", time_s=31, entity="service", cohort="site", available=False
    )
    partial = probe_summary(schedule, [good], "service", 0, "site", 60)
    assert partial["coverage"] == "partial"
    assert partial["metrics"] == {}
    full = probe_summary(schedule, [good, bad], "service", 0, "site", 60)
    assert full["coverage"] == "complete"
    assert full["metrics"] == {"unavailable_fraction": 0.5}
    with pytest.raises(ValueError, match="scope"):
        probe_summary(
            schedule, [good, dict(bad, entity="another")], "service", 0, "site", 60
        )


def test_http_load_and_measured_degradation_are_separate_from_security_indicators():
    import pytest
    from netwatch_ml.security import assess
    from netwatch_ml.telemetry import combine, http_summary, observer

    def http_window(start, count, status):
        return dict(
            entity="service",
            cohort="scope",
            start_s=start,
            complete=True,
            events=[
                dict(id=str(i), client=str(i), time_s=start, status=status)
                for i in range(count)
            ],
        )

    args = ("service", 60, "scope")
    ordinary = [http_window(0, 4, 200)]
    health = observer(*args, "probe", {"unavailable_fraction": 0}, 120)
    unavailable = observer(*args, "probe", {"unavailable_fraction": 0.5}, 120)
    change = observer(*args, "change", {}, 120)
    busy = http_summary(http_window(60, 20, 200), ordinary, *args, 120)
    errors = http_summary(http_window(60, 20, 503), ordinary, *args, 120)
    missing = assess(combine([busy, change], "service", 60))
    assert missing["availability"] == "unmeasured"
    assert [(f["label"], f["kind"]) for f in missing["findings"]] == [
        ("http_load", "traffic_pattern")
    ]
    healthy = assess(combine([errors, health, change], "service", 60))
    assert healthy["availability"] == "reachable"
    assert {f["label"] for f in healthy["findings"]} == {"http_load"}
    outage = assess(combine([errors, unavailable, change], "service", 60))
    assert outage["availability"] == "degraded"
    assert {f["label"]: f["kind"] for f in outage["findings"]} == {
        "http_load": "traffic_pattern",
        "web_ddos": "degradation_pattern",
    }
    no_probe = assess(combine([errors, change], "service", 60))
    assert "unavailable_fraction" in no_probe["unassessed"]["web_ddos"]
    planned = dict(change, expected_change=True)
    maintenance = assess(combine([errors, unavailable, planned], "service", 60))
    assert maintenance["scheduled_change"] and maintenance["availability"] == "degraded"
    assert {f["label"] for f in maintenance["findings"]} == {"http_load"}
    with pytest.raises(ValueError, match="change"):
        combine([dict(unavailable, expected_change=True)], "service", 60)

    assert (
        "http_rate_ratio"
        not in http_summary(
            http_window(60, 20, 200), [http_window(0, 0, 200)], *args, 120
        )["metrics"]
    )
    partial = http_summary(
        dict(http_window(60, 20, 200), complete=False), ordinary, *args, 120
    )
    assert not partial["metrics"] and partial["coverage"] == "partial"
    duplicate = http_window(60, 1, 200)
    duplicate["events"] *= 2
    with pytest.raises(ValueError, match="duplicate"):
        http_summary(duplicate, ordinary, *args, 120)
    with pytest.raises(ValueError, match="distinct"):
        http_summary(http_window(60, 20, 200), ordinary * 2, *args, 120)
