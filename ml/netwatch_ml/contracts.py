import json
import math
import ipaddress
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]

def validate(kind: str, value: dict):
    if kind not in {"window", "prediction", "packet"}:
        raise ValueError("unknown contract")
    schema = json.loads((ROOT / "contracts" / f"{kind}.schema.json").read_text())
    Draft202012Validator(schema).validate(value)
    # jsonschema accepts Python NaN as number; reject it before inference.
    json.dumps(value, allow_nan=False)
    for key in ("window_start_ns", "window_end_ns", "timestamp_ns"):
        if key in value and not 0 <= int(value[key]) <= 2**63-1:
            raise ValueError("timestamp outside int64")
    if kind == "packet" and value["decode_status"] == "decoded":
        ipaddress.ip_address(value["src_ip"])
        ipaddress.ip_address(value["dst_ip"])
        if value["protocol"] in {"TCP","UDP"} and (value["src_port"] is None or value["dst_port"] is None):
            raise ValueError("missing transport port")
    if kind == "window":
        if int(value["window_end_ns"]) <= int(value["window_start_ns"]):
            raise ValueError("window end must exceed start")
        for key, number in value["features"].items():
            if number is not None and (key.endswith(("packets", "bytes", "flows", "attempts")) or key.startswith("unique_") or key=="completed_flow_count"):
                if isinstance(number,bool) or not isinstance(number,int) or number>2**63-1:
                    raise ValueError("count must be int64")
    if kind == "prediction":
        scored = value["status"] in {"normal", "anomalous"}
        if scored and (value["score"] is None or value["threshold"] is None):
            raise ValueError("scored status needs numbers")
        if not scored and (value["score"] is not None or value["threshold"] is not None):
            raise ValueError("unavailable prediction must not have a score")
    return value
