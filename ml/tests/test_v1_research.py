import copy
import json

import numpy as np
import pytest

from netwatch_ml.contracts import ROOT
from netwatch_ml.v1.model import COUNTS, FEATURE_SET, LABELS
from netwatch_ml.v1.research import group_folds, load_rows, train_research
from netwatch_ml.v1.research_candidates import balanced_sample


def observations():
    template = json.loads((ROOT / "contracts/examples/window.valid.json").read_text())
    template["feature_set_version"] = FEATURE_SET
    template["features"].update(dict.fromkeys(COUNTS, 0))
    template["quality"]["capture_dropped"] = 0
    result = []
    for label in LABELS:
        window = copy.deepcopy(template)
        window["event_id"] = label
        result.append({"capture": "c1", "source": "publisher", "group": "capture-1", "split": "development", "label": label,
                       "episode": label, "family": "outside-catalogue" if label == "unknown" else None,
                       "window": window, "route": {"event_id": label, "status": "no_match", "attack_type": None}})
    return result


def dataset(tmp_path, rows):
    path = tmp_path / "prepared.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    return path


def test_holdout_and_loss_guards(tmp_path):
    rows = observations()
    missing = copy.deepcopy(rows)
    del missing[0]["split"]
    with pytest.raises(ValueError, match="requires an explicit split"):
        load_rows(dataset(tmp_path, missing), False)
    holdout = copy.deepcopy(rows[0])
    holdout["window"]["event_id"] = "held-out"
    holdout["route"]["event_id"] = "held-out"
    holdout.update(capture="c2", group="capture-2", split="test")
    for split in ("test", "pipeline"):
        holdout["split"] = split
        assert load_rows(dataset(tmp_path, [*rows, holdout]), False) == rows
    holdout["group"] = rows[0]["group"]
    with pytest.raises(ValueError, match="crosses folds or development and holdout"):
        load_rows(dataset(tmp_path, [*rows, holdout]), False)
    rows[0]["window"]["quality"]["capture_dropped"] = None
    with pytest.raises(ValueError, match="eligibility"):
        load_rows(dataset(tmp_path, rows), False)
    assert load_rows(dataset(tmp_path, rows), True) == rows
    rows[0]["window"]["quality"]["late_packets"] = 1
    with pytest.raises(ValueError, match="ineligible archival window"):
        load_rows(dataset(tmp_path, rows), True)


def test_folds_and_repeated_episode_names():
    labels = np.tile(LABELS, 10)
    groups = np.repeat([f"source-{index}" for index in range(10)], len(LABELS))
    folds = group_folds(labels, groups, 42)
    for train, held_out in folds:
        assert not set(groups[train]) & set(groups[held_out])
    assert sorted(np.concatenate([test for _, test in folds])) == list(range(len(labels)))
    repeated = [{"source": "one", "group": group, "episode": "same"} for group in ("A", "A", "B")]
    indices, weights = balanced_sample(repeated, np.repeat("type", 3), range(3), 10, 42)
    np.testing.assert_equal(indices, [0, 1, 2])
    np.testing.assert_allclose(weights, [0.25, 0.25, 0.5])


def test_invalid_input_never_publishes(tmp_path):
    output = tmp_path / "models"
    rows = observations()
    with pytest.raises(ValueError, match="independent source groups"):
        train_research(dataset(tmp_path, rows), output)
    assert not output.exists()
    del rows[0]["window"]["window_end_ns"]
    with pytest.raises(ValueError, match="invalid window at line 1"):
        train_research(dataset(tmp_path, rows), output)
    assert not output.exists()
    output.mkdir()
    with pytest.raises(ValueError, match="already exists"):
        train_research(tmp_path / "absent", output)
