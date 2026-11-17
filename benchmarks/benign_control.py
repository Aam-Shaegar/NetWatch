"""False incidents on the independently recorded Philips Hue host."""

from gotham import capture_minutes
from kitsune import Host, assess, with_reference


def benign_control(path):
    host = "192.168.1.132"
    windows = capture_minutes(path)
    complete = sorted(windows)
    sample = [windows[t].get(host, Host()).metrics() for t in complete[:5]]
    rules = ("packet_flood", "port_scan", "udp_flood", "icmp_flood", "syn_flood")
    results = {
        rule: dict(assessed_minutes=0, active_minutes=0, false_incidents=0)
        for rule in rules
    }
    previous = set()
    for start in complete[5:]:
        current = windows[start].get(host, Host()).metrics()
        response = assess(
            dict(
                schema_version=1,
                entity=host,
                start_s=start,
                interval_s=60,
                metrics=with_reference(current, sample),
            )
        )
        alerts = {item["label"] for item in response["findings"]}
        for label, row in results.items():
            if label not in response["unassessed"]:
                row["assessed_minutes"] += 1
                row["active_minutes"] += current["in_pps"] > 0
                row["false_incidents"] += label in alerts and label not in previous
        previous = alerts
    return results
