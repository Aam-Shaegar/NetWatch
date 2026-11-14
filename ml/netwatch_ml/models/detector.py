"""Frozen traffic-v1 transformations and portable Isolation Forest scoring."""
import hashlib
import hmac
import json
import math
from pathlib import Path

import numpy as np

from netwatch_ml.contracts import ROOT

FEATURES = sorted(json.loads((ROOT / 'contracts/window.schema.json').read_text())
                  ['properties']['features']['required'])
VERSION = 'traffic-v1'
POLICY = 'v1'
WIDTH = len(FEATURES)


def matrix(rows):
    return np.array([[r[f] for f in FEATURES] for r in rows], dtype=float)


def fit_transform_parameters(raw):
    values = np.log1p(raw)
    # An always-missing feature has a constant imputed value and a missingness bit.
    median = np.array([np.median(col[np.isfinite(col)]) if np.isfinite(col).any() else 0.
                       for col in values.T])
    filled = np.where(np.isnan(values), median, values)
    low, high = np.quantile(filled, [.25, .75], axis=0)
    return {'median': median.tolist(), 'scale': np.where(high > low, high - low, 1.).tolist()}


def transform(raw, params):
    values = np.log1p(raw)
    missing = np.isnan(values)
    median = np.asarray(params['median'])
    standardized = (np.where(missing, median, values) - median) / params['scale']
    return np.column_stack([standardized, missing])


def mean_path(count):
    if count <= 1:
        return 0.
    if count == 2:
        return 1.
    return 2 * (math.log(count - 1) + np.euler_gamma) - 2 * (count - 1) / count


def export_forest(model):
    trees = []
    for estimator in model.estimators_:
        t = estimator.tree_
        depth = t.compute_node_depths() - 1
        trees.append([[int(t.feature[i]), float(t.threshold[i]), int(t.children_left[i]),
                       int(t.children_right[i]), float(depth[i] + mean_path(t.n_node_samples[i]))]
                      for i in range(t.node_count)])
    return {'normalizer': mean_path(model.max_samples_), 'trees': trees}


def forest_score(x, forest):
    # sklearn converts feature values to float32 before evaluating split thresholds.
    x = np.asarray(x, dtype=np.float32)
    total = 0.
    for tree in forest['trees']:
        node = tree[0]
        while node[2] != -1:
            node = tree[node[2] if x[node[0]] <= node[1] else node[3]]
        total += node[4]
    return 2 ** (-total / (len(forest['trees']) * forest['normalizer']))


def model_id(payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    prefix = 'gru-' if payload.get('architecture') == 'gru' else 'if-'
    return prefix + hashlib.sha256(encoded).hexdigest()[:24]


def load_bundle(path, expected_sha):
    if not expected_sha or Path(path).stat().st_size > 32 << 20:
        raise ValueError('invalid bundle size or missing pinned digest')
    data = Path(path).read_bytes()
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha):
        raise ValueError('bundle checksum mismatch')
    bundle = json.loads(data)
    payload = bundle['detector']
    if (bundle['model_id'] != model_id(payload) or payload['format'] != 1 or
            payload['feature_set_version'] != VERSION or payload['features'] != FEATURES or
            payload['policy_version'] != POLICY or payload['profile'] != 'tcp-service-8080-5s'):
        raise ValueError('incompatible model')
    params = payload['preprocessing']
    for key in ('median', 'scale'):
        arr = np.asarray(params[key], dtype=float)
        if arr.shape != (WIDTH,) or not np.isfinite(arr).all() or (key == 'scale' and np.any(arr <= 0)):
            raise ValueError('invalid preprocessing')
    threshold = payload['threshold']
    if payload.get('architecture') == 'gru':
        from netwatch_ml.models.gru import HISTORY, unpack
        if not math.isfinite(threshold) or threshold < 0 or payload['history'] != HISTORY:
            raise ValueError('invalid GRU configuration')
        bundle['runtime'] = unpack(payload)
        return bundle
    forest = payload['forest']
    if not (math.isfinite(threshold) and threshold >= 0 and 0 < forest['normalizer'] < 100
            and 1 <= len(forest['trees']) <= 512):
        raise ValueError('invalid detector parameters')
    for tree in forest['trees']:
        if not 1 <= len(tree) <= 8191:
            raise ValueError('invalid tree size')
        for i, (feature, split, left, right, path_length) in enumerate(tree):
            if not math.isfinite(split) or not math.isfinite(path_length) or path_length < 0:
                raise ValueError('invalid tree value')
            if left == right == -1:
                continue
            if (any(type(v) is not int for v in (feature, left, right)) or
                    not (0 <= feature < WIDTH * 2 and i < left < len(tree) and i < right < len(tree))):
                raise ValueError('invalid tree links')
    return bundle


def supported_window(window):
    quality = window['quality']
    supported = (window['entity_type'] == 'destination_service' and
                 window['entity_id'].startswith('TCP/') and window['entity_id'].endswith(':8080') and
                 int(window['window_end_ns']) - int(window['window_start_ns']) == 5_000_000_000)
    return supported and quality['coverage'] == 'complete' and all(
        quality[k] == 0 for k in ('capture_dropped', 'late_packets', 'state_evictions'))


def predict_window(window, bundle, history=()):
    if 'runtime' in bundle:
        from netwatch_ml.models.gru import predict_sequence
        return predict_sequence(window, history, bundle)
    result = dict(schema_version=1, event_id=window['event_id'], model_id=bundle['model_id'],
                  feature_set_version=VERSION, status='insufficient_data', score=None, threshold=None)
    if not supported_window(window):
        return result
    payload = bundle['detector']
    x = transform(matrix([window['features']]), payload['preprocessing'])[0]
    score = forest_score(x, payload['forest'])
    threshold = payload['threshold']
    result.update(score=score, threshold=threshold, status='anomalous' if score > threshold else 'normal')
    return result
