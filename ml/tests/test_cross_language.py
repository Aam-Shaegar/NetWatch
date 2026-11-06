import json,subprocess
import pytest
from netwatch_ml.contracts import ROOT,validate

def test_go_python_validate_same_golden_window():
    path=ROOT/'contracts/examples/window.valid.json'
    validate('window',json.loads(path.read_text()))
    subprocess.run(['go','run','./cmd/netwatch-sensor','-validate','window',str(path)],cwd=ROOT,check=True,capture_output=True)
