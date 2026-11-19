"""Train and calibrate Isolation Forest on separate normal captures of one service."""
import argparse
import hashlib
import json
from pathlib import Path
import re

import sklearn

from netwatch_ml.contracts import validate
from netwatch_ml.models.detector import (FEATURE_SETS, POLICY, SCOPED_PROFILE,
                                        fit_transform_parameters, matrix, supported_window,
                                        transform, validate_binding)
from netwatch_ml.training.baselines import (BUDGET, WINDOW_NS, calibrate, export_scores,
                                            fit_forest, publish_bundle)


def read_normal_captures(manifest, root, binding, version):
    if set(manifest) != {'train', 'calibration'}:
        raise ValueError('separate train and calibration captures are required')
    partitions = {}
    event_ids, epochs, sources, window_starts = set(), set(), set(), set()
    for part in ('train', 'calibration'):
        partitions[part] = []
        if not isinstance(manifest[part], list) or not manifest[part]:
            raise ValueError(f'{part} requires at least one normal capture')
        for capture in manifest[part]:
            source = capture['source_sha256']
            if (capture['label'] != 'normal' or not re.fullmatch('[0-9a-f]{64}', source)
                    or source in sources):
                raise ValueError('normal captures require distinct source SHA-256 digests')
            sources.add(source)
            path = Path(capture['windows'])
            if path.is_absolute() or not path.parts or '..' in path.parts:
                raise ValueError('windows must use a relative path below the manifest directory')
            resolved = (root / path).resolve()
            if not resolved.is_relative_to(root.resolve()):
                raise ValueError('windows path resolves outside the manifest directory')
            data = resolved.read_bytes()
            if hashlib.sha256(data).hexdigest() != capture['windows_sha256']:
                raise ValueError('windows checksum mismatch')
            rows = [validate('window', json.loads(line)) for line in data.splitlines() if line.strip()]
            capture_epochs = {window['capture_epoch'] for window in rows}
            if len(capture_epochs) != 1 or epochs & capture_epochs:
                raise ValueError('each capture requires one distinct epoch')
            epochs.update(capture_epochs)
            for window in rows:
                event_id = window['event_id']
                start = int(window['window_start_ns'])
                if not supported_window(window, binding, version):
                    raise ValueError('profile requires complete, loss-free windows of the bound service')
                if event_id in event_ids or start in window_starts or start % WINDOW_NS:
                    raise ValueError('duplicate or unaligned window')
                event_ids.add(event_id)
                window_starts.add(start)
                partitions[part].append((start, window['features']))
    return {part: [features for _, features in sorted(rows)] for part, rows in partitions.items()}


def train(manifest_path, destination, seed=42):
    if destination.exists():
        raise FileExistsError(destination)
    data = manifest_path.read_bytes()
    manifest = json.loads(data)
    version = manifest['feature_set_version']
    if manifest['schema_version'] != 1 or version not in FEATURE_SETS:
        raise ValueError('incompatible dataset manifest')
    binding = manifest['binding']
    validate_binding(binding)
    captures = manifest['captures']
    parts = read_normal_captures(captures, manifest_path.parent, binding, version)
    features = FEATURE_SETS[version]
    training = matrix(parts['train'], features)
    params = fit_transform_parameters(training)
    model, forest = fit_forest(transform(training, params), seed)
    calibration = transform(matrix(parts['calibration'], features), params)
    scores = export_scores(calibration, model, forest)
    threshold = calibrate(scores)
    payload = dict(format=1, feature_set_version=version, features=features, policy_version=POLICY,
                   profile=SCOPED_PROFILE, binding=binding, preprocessing=params, forest=forest,
                   threshold=threshold, seed=seed, sklearn_version=sklearn.__version__,
                   dataset_manifest_sha256=hashlib.sha256(data).hexdigest())
    normal_hours = len(scores) * WINDOW_NS / (3600 * 1e9)
    false_windows = int((scores > threshold).sum())
    report = dict(profile=SCOPED_PROFILE, binding=binding, feature_set_version=version, train_windows=len(training),
                  calibration_windows=len(scores), calibration_normal_hours=normal_hours,
                  calibration_false_windows=false_windows,
                  false_window_budget_per_normal_hour=BUDGET, threshold=threshold,
                  source_sha256={part: [capture['source_sha256'] for capture in group]
                                 for part, group in captures.items()})
    return publish_bundle(destination, payload, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(train(args.manifest, args.output), indent=2))


if __name__ == '__main__':
    main()
