"""Fit lab baselines, calibrate on independent normal exposure and export a detector."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import tempfile

import numpy as np
import pyarrow.parquet as pq
import sklearn
from sklearn.ensemble import IsolationForest

from netwatch_ml.models.detector import (FEATURES, POLICY, VERSION, export_forest, fit_transform_parameters,
                                        forest_score, load_bundle, matrix, model_id, transform)

PARTS = ('train', 'validation', 'calibration', 'test')
BUDGET = 1.0
WINDOW_NS = 5_000_000_000


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_partitions(folder):
    manifest = json.loads((folder / 'manifest.json').read_text())
    if (manifest['schema_version'] != 1 or manifest['feature_set_version'] != VERSION or
            manifest['feature_columns'] != FEATURES or set(manifest['splits']) != set(PARTS)):
        raise ValueError('incompatible dataset manifest')
    seen_groups, seen_ids = set(), set()
    parts = {}
    for part in PARTS:
        meta = manifest['splits'][part]
        path = folder / (part + '.parquet')
        if sha(path) != meta['sha256']:
            raise ValueError('partition checksum mismatch')
        rows = sorted(pq.read_table(path).to_pylist(), key=lambda r: (r['group_id'], r['window_start_ns']))
        groups = {r['group_id'] for r in rows}
        ids = {r['event_id'] for r in rows}
        labels = Counter(r['label'] for r in rows)
        if (not rows or len(rows) != meta['rows'] or groups != set(meta['groups']) or
                seen_groups & groups or seen_ids & ids or len(ids) != len(rows) or labels != meta['labels'] or
                set(labels) - {'normal', 'foreground_pause'} or
                (part in ('train', 'calibration') and set(labels) != {'normal'})):
            raise ValueError('invalid partition groups, labels or identities')
        x = matrix(rows)
        if np.any(np.isinf(x)) or np.any(x < 0):
            raise ValueError('invalid feature values')
        parts[part] = rows
        seen_groups.update(groups)
        seen_ids.update(ids)
    return parts


def ewma_scores(rows, values, alpha=.2):
    scores = []
    previous = None
    for r, x in zip(rows, values, strict=True):
        key = (r['group_id'], r['entity_id'], r['window_start_ns'])
        if previous != (key[0], key[1], key[2] - WINDOW_NS):
            mean = np.zeros_like(x)  # Start from the frozen training median.
        scores.append(float(np.max(np.abs(x - mean))))
        mean = (1 - alpha) * mean + alpha * x
        previous = key
    return np.array(scores)


def calibrate(scores, budget=BUDGET):
    allowed = math.floor(budget * len(scores) * 5 / 3600)
    return float(np.sort(scores)[-1 - allowed])


def metrics(rows, scores, threshold):
    actual = np.array([r['label'] != 'normal' for r in rows])
    alerts = scores > threshold
    normal_hours = float((~actual).sum() * 5 / 3600)
    false = int((alerts & ~actual).sum())
    return dict(windows=len(rows), normal_hours=normal_hours, false_windows=false,
                false_windows_per_hour=false / normal_hours if normal_hours else None,
                abnormal_windows=int(actual.sum()), detected_windows=int((alerts & actual).sum()))


def train(folder, destination, seed=42):
    if destination.exists():
        raise FileExistsError(destination)
    parts = read_partitions(folder)
    params = fit_transform_parameters(matrix(parts['train']))
    values = {part: transform(matrix(rows), params) for part, rows in parts.items()}
    model = IsolationForest(n_estimators=100, max_samples=min(256, len(parts['train'])),
                            random_state=seed, n_jobs=1)
    if model.max_samples < 2:
        raise ValueError('insufficient training windows')
    model.fit(values['train'])
    forest = export_forest(model)
    report = {'false_window_budget_per_normal_hour': BUDGET, 'models': {}}
    for method in ('fixed', 'ewma', 'isolation_forest'):
        scores = {}
        for part in ('calibration', 'validation', 'test'):
            x = values[part]
            if method == 'fixed':
                scores[part] = np.max(np.abs(x), axis=1)
            elif method == 'ewma':
                scores[part] = ewma_scores(parts[part], x)
            else:
                scores[part] = np.array([forest_score(row, forest) for row in x])
                np.testing.assert_allclose(scores[part], -model.score_samples(x), rtol=0, atol=1e-12)
        threshold = calibrate(scores['calibration'])
        report['models'][method] = dict(threshold=threshold, **{
            part: metrics(parts[part], vector, threshold) for part, vector in scores.items()})
    manifest = json.loads((folder / 'manifest.json').read_text())
    payload = dict(format=1, feature_set_version=VERSION, features=FEATURES, policy_version=POLICY,
                   profile='tcp-service-8080-5s', preprocessing=params, forest=forest,
                   threshold=report['models']['isolation_forest']['threshold'], seed=seed,
                   dataset_manifest_sha256=sha(folder / 'manifest.json'), sklearn_version=sklearn.__version__,
                   splits={p: manifest['splits'][p]['groups'] for p in PARTS})
    bundle = dict(model_id=model_id(payload), detector=payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        out = Path(tmp) / 'result'
        out.mkdir()
        artifact = out / 'bundle.json'
        artifact.write_text(json.dumps(bundle, allow_nan=False, separators=(',', ':')))
        checksum = sha(artifact)
        load_bundle(artifact, checksum)
        report.update(model_id=bundle['model_id'], bundle_sha256=checksum,
                      dataset_manifest_sha256=payload['dataset_manifest_sha256'])
        (out / 'report.json').write_text(json.dumps(report, allow_nan=False, indent=2) + '\n')
        out.rename(destination)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(train(args.dataset, args.output), indent=2))


if __name__ == '__main__':
    main()
