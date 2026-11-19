import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "independent_benchmark", ROOT / "benchmarks" / "independent.py"
)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


def test_known_source_overlap_is_rejected_before_scoring(tmp_path):
    training = tmp_path / "training.json"
    training.write_text(
        json.dumps({"groups": {"training": {"sha256": "train", "source_hashes": {}}}})
    )
    used = next(iter(benchmark.read(ROOT / "benchmarks/external-inputs.json").values()))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "unseen_by_developers": True,
                "passive_sha256": {
                    name: benchmark.digest(ROOT / name)
                    for name in benchmark.PASSIVE_FILES
                },
                "development_groups": [],
                "holdout_groups": [
                    {
                        "id": "renamed",
                        "sources": [{"path": "renamed.pcap", "sha256": used}],
                    }
                ],
            }
        )
    )
    report = benchmark.empty_report()
    with pytest.raises(ValueError, match="source overlap"):
        benchmark.evaluate(manifest, tmp_path, tmp_path, training, report)
    assert len(report["types"]) == 25
    assert report["cases"] == []


def test_missing_observation_is_distinct_from_negative_result():
    payload = dict(
        schema_version=1,
        entity="service",
        start_s=0,
        interval_s=60,
        metrics={},
        crs_rule_ids=[],
    )
    observed = benchmark.outcomes("passive", payload, {})
    assert observed["port_scan"] is None
    assert observed["xss"] is False


def test_missing_manifest_exits_unsuccessfully_and_records_all_types(
    tmp_path, monkeypatch
):
    report = tmp_path / "result.json"
    monkeypatch.setattr(
        "sys.argv", ["independent.py", *(str(tmp_path / "missing"),) * 4, str(report)]
    )
    assert benchmark.main() == 1
    result = benchmark.read(report)
    assert result["passed"] is False
    assert len(result["types"]) == 25
    assert {row["status"] for row in result["types"].values()} == {"missing coverage"}


def test_previously_evaluated_manifest_requires_regression_mode(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"version": 1, "unseen_by_developers": False, "passive_sha256": {}})
    )
    with pytest.raises(ValueError, match="attestation"):
        benchmark.evaluate(
            manifest, tmp_path, tmp_path, tmp_path, benchmark.empty_report()
        )
    with pytest.raises(ValueError, match="frozen"):
        benchmark.evaluate(
            manifest,
            tmp_path,
            tmp_path,
            tmp_path,
            benchmark.empty_report(),
            regression=True,
        )
