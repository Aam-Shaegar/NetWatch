from fastapi.testclient import TestClient
from netwatch_ml.serving.app import create_app
from netwatch_ml.security_import import from_waf


def test_missing_service_health_does_not_confirm_ddos():
    client = TestClient(create_app())
    obs = dict(schema_version=1, entity="test", start_s=0, interval_s=60,
               metrics=dict(in_pps=150, pps_baseline_ratio=6, source_ips=20))
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
    msg = {"details": {"ruleId":"942100", "tags":["local"]}}
    record = {"transaction": {"messages":[msg]}}
    assert from_waf(record, "lab", 0)["crs_rule_ids"] == []
    msg["details"]["tags"] = ["OWASP_CRS"]
    assert from_waf(record, "lab", 0)["crs_rule_ids"] == [942100]


def test_events_keep_accounts_and_time_windows_separate():
    import json
    from netwatch_ml.security_import import from_events
    from netwatch_ml.security import assess

    rows = [dict(entity="service", time_s=i, principal=str(i % 2), success=False)
            for i in range(20)]
    def findings(events):
        obs = from_events(map(json.dumps, events), "service", 0, "auth")
        return [item["label"] for item in assess(obs)["findings"]]
    assert findings(rows) == ["password_guessing"]
    assert findings(rows[:18] + [dict(rows[0], time_s=60)]) == []


def test_periodicity_needs_consistent_destination_policy():
    import json
    from netwatch_ml.security_import import from_events
    from netwatch_ml.security import assess

    rows = [dict(entity="service:peer", time_s=i*5, unapproved_destination=True)
            for i in range(10)]
    def observation():
        return from_events(map(json.dumps, rows), "service:peer", 0, "egress")
    assert assess(observation())["findings"][0]["label"] == "possible_beacon"
    rows[-1]["unapproved_destination"] = False
    assert "possible_beacon" in assess(observation())["unassessed"]
