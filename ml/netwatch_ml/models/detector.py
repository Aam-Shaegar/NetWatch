"""Versioned feature transformations and portable Isolation Forest scoring."""
import hashlib
import hmac
import ipaddress
import json
import math
from pathlib import Path

import numpy as np

from netwatch_ml.contracts import ROOT

VERSION = 'traffic-v1'
LIFECYCLE_VERSION = 'traffic-v2'
_schema = json.loads((ROOT / 'contracts/window.schema.json').read_text())
FEATURES = sorted(_schema['properties']['features']['required'])
FEATURE_SETS = {
    VERSION: FEATURES,
    LIFECYCLE_VERSION: sorted(FEATURES + _schema['$defs']['tcpConnectionAges']['required']),
}
POLICY = 'v1'
WIDTH = len(FEATURES)
LAB_PROFILE = 'tcp-service-8080-5s'
SCOPED_PROFILE = 'scoped-tcp-service-5s'


def matrix(rows, features=FEATURES):
    return np.array([[r[f] for f in features] for r in rows], dtype=float)


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


def validate_binding(binding):
    if not isinstance(binding, dict) or binding.keys() != {'sensor_id', 'entity_id'}:
        raise ValueError('a service binding requires sensor_id and entity_id')
    sensor = binding['sensor_id']
    entity = binding['entity_id']
    if (not isinstance(sensor, str) or not sensor.strip() or len(sensor) > 200 or '\0' in sensor
            or not isinstance(entity, str)):
        raise ValueError('invalid service binding')
    address, _, port = entity.removeprefix('TCP/').rpartition(':')
    if not entity.startswith('TCP/') or not port.isascii() or not port.isdecimal() or len(port) > 5:
        raise ValueError('expected a TCP destination service')
    ip = ipaddress.ip_address(address.removeprefix('[').removesuffix(']'))
    host = f'[{ip}]' if ip.version == 6 else str(ip)
    if ip.is_unspecified or '%' in host or not 1 <= int(port) <= 65535 or entity != f'TCP/{host}:{int(port)}':
        raise ValueError('expected a canonical TCP destination service')


def load_bundle(path, expected_sha):
    if not expected_sha or Path(path).stat().st_size > 32 << 20:
        raise ValueError('invalid bundle size or missing pinned digest')
    data = Path(path).read_bytes()
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha):
        raise ValueError('bundle checksum mismatch')
    bundle = json.loads(data)
    payload = bundle['detector']
    features = FEATURE_SETS.get(payload['feature_set_version'])
    if (bundle['model_id'] != model_id(payload) or payload['format'] != 1 or
            features is None or payload['features'] != features or
            payload['policy_version'] != POLICY):
        raise ValueError('incompatible model')
    if payload['profile'] == SCOPED_PROFILE:
        validate_binding(payload.get('binding'))
        if {'architecture', 'classifier', 'pattern_limits'} & payload.keys():
            raise ValueError('scoped model requires an Isolation Forest without lab rules')
    elif payload['profile'] != LAB_PROFILE or 'binding' in payload or payload['feature_set_version'] != VERSION:
        raise ValueError('incompatible model profile')
    width = len(features)
    params = payload['preprocessing']
    for key in ('median', 'scale'):
        arr = np.asarray(params[key], dtype=float)
        if arr.shape != (width,) or not np.isfinite(arr).all() or (key == 'scale' and np.any(arr <= 0)):
            raise ValueError('invalid preprocessing')
    threshold = payload['threshold']
    if payload.get('architecture') == 'gru':
        from netwatch_ml.models.gru import HISTORY, unpack
        if not math.isfinite(threshold) or threshold < 0 or payload['history'] != HISTORY:
            raise ValueError('invalid GRU configuration')
        bundle['runtime'] = unpack(payload)
        return bundle
    if 'classifier' in payload:
        from netwatch_ml.models.classifier import validate_classifier, version
        validate_classifier(payload['classifier'])
        bundle['classifier_version'] = version(payload['classifier'])
    if 'pattern_limits' in payload:
        from netwatch_ml.models.patterns import validate_limits
        if 'classifier' not in payload:
            raise ValueError('service patterns require the base classifier')
        validate_limits(payload['pattern_limits'])
        if threshold <= 0:
            raise ValueError('service patterns require a positive threshold')
        bundle['classifier_version'] = version([payload['classifier'], payload['pattern_limits']])
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
                    not (0 <= feature < width * 2 and i < left < len(tree) and i < right < len(tree))):
                raise ValueError('invalid tree links')
    return bundle


def window_unavailability(window, binding=None, version=VERSION):
    if window.get('feature_set_version') != version:
        return 'feature_set_mismatch'
    quality = window['quality']
    if binding is None:
        entity_supported = window['entity_id'].startswith('TCP/') and window['entity_id'].endswith(':8080')
    else:
        entity_supported = all(window[key] == value for key, value in binding.items())
    if window['entity_type'] != 'destination_service' or not entity_supported:
        return 'outside_model_scope'
    if any(quality[k] not in (0, None) for k in ('capture_dropped', 'late_packets', 'state_evictions')):
        return 'capture_loss'
    if (quality['coverage'] != 'complete' or
            int(window['window_end_ns']) - int(window['window_start_ns']) != 5_000_000_000):
        return 'incomplete_coverage'
    if any(quality[k] is None for k in ('capture_dropped', 'late_packets', 'state_evictions')):
        return 'unverified_capture_quality'
    return None


def supported_window(window, binding=None, version=VERSION):
    return window_unavailability(window, binding, version) is None


def predict_window(window, bundle, history=()):
    if 'runtime' in bundle:
        from netwatch_ml.models.gru import predict_sequence
        return predict_sequence(window, history, bundle)
    result = dict(schema_version=1, event_id=window['event_id'], model_id=bundle['model_id'],
                  feature_set_version=window['feature_set_version'], status='insufficient_data',
                  score=None, threshold=None)
    payload = bundle.get('detector', {})
    version = payload.get('feature_set_version', VERSION)
    reason = window_unavailability(window, payload.get('binding'), version)
    if reason:
        result['unavailable_reason'] = reason
        if 'classifier_version' in bundle:
            outside_profile = window['entity_type'] != 'destination_service' or not (
                window['entity_id'].startswith('TCP/') and window['entity_id'].endswith(':8080'))
            quality = window['quality']
            has_loss = any(quality[k] not in (0, None) for k in ('capture_dropped', 'late_packets', 'state_evictions'))
            full_window = int(window['window_end_ns']) - int(window['window_start_ns']) == 5_000_000_000
            label = 'unknown' if outside_profile and full_window and quality['coverage'] == 'complete' and not has_loss else 'insufficient_data'
            result['classification'] = dict(label=label, probability=None, version=bundle['classifier_version'])
        return result
    x = transform(matrix([window['features']], FEATURE_SETS[version]), payload['preprocessing'])[0]
    score = forest_score(x, payload['forest'])
    threshold = payload['threshold']
    result["diagnostics"] = {"forest_score": score, "forest_threshold": threshold}
    if 'pattern_limits' in payload:
        from netwatch_ml.models.patterns import match
        label, ratio = match(window['features'], payload['pattern_limits'])
        if label is None:
            result['classification'] = dict(label='insufficient_data', probability=None, version=bundle['classifier_version'])
            return result
        result["diagnostics"].update(pattern_label=label, pattern_ratio=ratio)
        if ratio > 1:
            result.update(score=max(score, threshold * ratio), threshold=threshold, status='anomalous',
                          classification=dict(label=label, probability=None, version=bundle['classifier_version']))
            return result
    result.update(score=score, threshold=threshold, status='anomalous' if score > threshold else 'normal')
    if result['status'] == 'anomalous' and 'classifier_version' in bundle:
        from netwatch_ml.models.classifier import classify
        result['classification'] = classify(x, payload['classifier'], bundle['classifier_version'])
    return result
