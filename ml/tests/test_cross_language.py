import json,subprocess
import pytest
from netwatch_ml.contracts import ROOT,validate

def test_go_python_validate_same_golden_window():
    path=ROOT/'contracts/examples/window.valid.json'
    validate('window',json.loads(path.read_text()))
    subprocess.run(['go','run','./cmd/netwatch-sensor','-validate','window',str(path)],cwd=ROOT,check=True,capture_output=True)

def test_replay_packet_contract(tmp_path):
    out = tmp_path / 'packets.jsonl'
    subprocess.run(['go','run','./cmd/netwatch-sensor','replay','--input',
                    'tests/fixtures/pcap/syn-retry.pcap','--output',str(out)],cwd=ROOT,check=True)
    packets = [validate('packet',json.loads(line)) for line in out.read_text().splitlines()]
    assert len(packets) == 2
    assert sum(p['ip_length'] for p in packets) == 80
    assert all(p['tcp_flags'] == 2 for p in packets)
