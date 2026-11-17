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
    assert {f["label"] for f in get()["findings"]} == {"dos", "ddos", "packet_flood"}
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
        normal = BurstRates().metrics()
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
    observation = from_packets([json.dumps(record)] * 550, [], "192.0.2.1", 300, 0, 5)
    assert observation["metrics"]["peak_udp_pps_5s"] == 110
    assert {f["label"] for f in assess(observation)["findings"]} == {
        "packet_flood",
        "udp_flood",
    }
