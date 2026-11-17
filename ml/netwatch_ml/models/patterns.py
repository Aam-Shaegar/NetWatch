"""Observable shifts for short-lived request/response TCP services."""
import math

LABELS = ("large_upload", "large_response", "connection_surge")
LIMIT_KEYS = (*LABELS, "total_in_bytes", "total_out_bytes")


def measurements(features):
    flows = max(1, features["active_flows"])
    return (features["in_ip_bytes"] / flows, features["out_ip_bytes"] / flows,
            features["new_tcp_attempts"], features["in_ip_bytes"], features["out_ip_bytes"])


def validate_limits(limits):
    if set(limits) != set(LIMIT_KEYS) or any(type(v) not in (int, float) or not math.isfinite(v)
                                         or v <= 0 for v in limits.values()):
        raise ValueError("invalid service pattern limits")


def match(features, limits):
    required = ("active_flows", "new_tcp_attempts", "in_packets", "out_packets", "in_ip_bytes", "out_ip_bytes")
    if any(features[key] is None for key in required):
        return None, 0.0
    if (features["active_flows"] == 1 and features["new_tcp_attempts"] == 0
            and min(features["in_packets"], features["out_packets"]) >= 8):
        return "persistent_exchange", 1.25
    relative = {k: v / limits[k] for k, v in zip(LIMIT_KEYS, measurements(features))}
    ratios = dict(large_upload=min(relative["large_upload"], relative["total_in_bytes"]),
                  large_response=min(relative["large_response"], relative["total_out_bytes"]),
                  connection_surge=relative["connection_surge"])
    label = max(ratios, key=ratios.get)
    return label, ratios[label]
