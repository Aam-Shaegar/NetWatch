import copy
import json
import subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from netwatch_ml.contracts import validate, ROOT
from netwatch_ml.serving.app import app

@pytest.fixture
def window(): return json.loads((ROOT/"contracts/examples/window.valid.json").read_text())
def test_valid(window): assert validate("window",window)==window
@pytest.mark.parametrize("change",[
 lambda w:w.update(schema_version=2),
 lambda w:w.update(window_end_ns=w["window_start_ns"]),
 lambda w:w.update(window_start_ns="9999999999999999999"),
 lambda w:w["features"].update(out_packets=1.5),
 lambda w:w["features"].update(mean_packet_size=float("nan")),
 lambda w:w.update(extra="bad")])
def test_invalid(window,change):
 change(window)
 with pytest.raises(Exception): validate("window",window)
def test_unready():
 c=TestClient(app)
 assert c.get("/health/live").status_code==200
 assert c.get("/health/ready").status_code==503
 assert c.post("/v1/predict",json={}).status_code==503
