"""Train a causal GRU and evaluate the four detectors against audited lab events."""
import argparse
import copy
import json
from pathlib import Path
import tempfile

import numpy as np
import torch
from torch.nn import functional as F

from netwatch_ml.models.detector import (FEATURES, POLICY, VERSION, WIDTH, forest_score, load_bundle,
                                         matrix, model_id, supported_window, transform)
from netwatch_ml.models.gru import GRUForecast, HISTORY, STEP, residuals, scores, sequences
from netwatch_ml.training.baselines import BUDGET, calibrate, ewma_scores, read_partitions, sha


def tensors(rows, params):
    return torch.tensor(transform(matrix(rows), params), dtype=torch.float32)


def fit(parts, params, seed):
    torch.manual_seed(seed)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    model = GRUForecast()
    optimizer = torch.optim.AdamW(model.parameters(), lr=.001)
    sets = []
    for name in ('train', 'validation'):
        rows = parts[name]
        x = tensors(rows, params)
        hist, target = sequences(rows)
        normal = np.array([r['label'] == 'normal' for r in rows])
        keep = normal[target] & normal[hist].all(axis=1)
        keep &= (x[target, WIDTH:] == 0).any(dim=1).numpy()
        if not keep.any():
            raise ValueError(f'no continuous normal sequences in {name}')
        sets.append((x[hist[keep]], x[target[keep]]))
    (past, target), (val_past, val_target) = sets
    history, best_epoch, best_loss = [], 0, float('inf')
    for epoch in range(1, 51):
        model.train()
        for ix in torch.randperm(len(target)).split(128):
            optimizer.zero_grad()
            losses = F.smooth_l1_loss(model(past[ix]), target[ix, :WIDTH], reduction='none')
            loss = losses[target[ix, WIDTH:] == 0].mean()
            loss.backward()
            optimizer.step()
        model.eval()
        with torch.no_grad():
            losses = F.smooth_l1_loss(model(val_past), val_target[:, :WIDTH], reduction='none')
            loss = losses[val_target[:, WIDTH:] == 0].mean().item()
        history.append(loss)
        if loss < best_loss:
            best_epoch, best_loss, best = epoch, loss, copy.deepcopy(model.state_dict())
        if epoch - best_epoch >= 5:
            break
    model.load_state_dict(best)
    with torch.no_grad():
        errors = residuals(model(val_past), val_target)
        # A feature absent throughout normal validation gets unit residual scale.
        scale = errors.nanmedian(dim=0).values.nan_to_num(nan=1.).clamp_min(.01)
    return model, scale, dict(seed=seed, best_epoch=best_epoch, validation_loss=history,
                              train_sequences=len(target), validation_normal_sequences=len(val_target))


def timeline(collection, manifest, parts, part):
    """Keep mixed boundary windows as causal input; labels only decide evaluation exposure."""
    labels = {r['event_id']: r['label'] for r in parts[part]}
    found = set()
    rows = []
    for group in manifest['splits'][part]['groups']:
        meta = manifest['groups'][group]
        path = collection / group / 'live.jsonl'
        if sha(path) != meta['source_hashes']['live.jsonl']:
            raise ValueError('capture windows differ from audited dataset')
        for line in path.read_text().splitlines():
            w = json.loads(line)
            if not supported_window(w):
                continue
            label = labels.get(w['event_id'])
            if label:
                found.add(w['event_id'])
            rows.append(dict(w['features'], group_id=group, entity_id=w['entity_id'],
                             window_start_ns=int(w['window_start_ns']), label=label))
    if found != labels.keys():
        raise ValueError('audited windows missing from timeline')
    return sorted(rows, key=lambda r: (r['group_id'], r['entity_id'], r['window_start_ns']))


@torch.inference_mode()
def predictions(rows, detector, model, scale):
    x = tensors(rows, detector['preprocessing'])
    hist, target = sequences(rows)
    gru = np.full(len(rows), np.nan)
    if len(target):
        gru[target] = scores(residuals(model(x[hist]), x[target]), scale).numpy()
    # Keep baseline precision identical to the deployed step-8 detector.
    values = transform(matrix(rows), detector['preprocessing'])
    return dict(fixed=np.abs(values).max(axis=1), ewma=ewma_scores(rows, values),
                isolation_forest=np.array([forest_score(v, detector['forest']) for v in values]), gru=gru)


def evaluate(rows, vector, threshold, groups):
    truth = {(g, e['start_ns'], e['end_ns']): None for g, m in groups.items() for e in m['events']}
    previous = None
    active = False
    recent = []
    recovery = false = false_windows = normal = scored_normal = scored = 0
    for r, score in zip(rows, vector, strict=True):
        stream = r['group_id'], r['entity_id']
        start = r['window_start_ns']
        end = start + STEP
        if previous != (stream, start):
            if previous is None or previous[0] != stream:
                active = False
            recent, recovery = [], 0
        previous = stream, end
        is_normal = r['label'] == 'normal'
        normal += int(is_normal)
        if not np.isfinite(score):
            recent, recovery = [], 0
            continue
        scored += 1
        scored_normal += int(is_normal)
        signal = bool(score > threshold)
        false_windows += int(is_normal and signal)
        if active:
            recovery = recovery + 1 if score <= .95 * threshold else 0
            if recovery == 3:
                active, recovery = False, 0
            continue
        recent = (recent + [signal])[-3:]
        if len(recent) == 3 and sum(recent) >= 2:
            active, recent = True, []
            hit = next((event for event in truth if event[0] == stream[0] and event[1] < end <= event[2]), None)
            if hit and truth[hit] is None:
                truth[hit] = (end - hit[1]) / 1e9
            elif not hit and is_normal:
                false += 1
    hours = normal * 5 / 3600
    delays = [v for v in truth.values() if v is not None]
    return dict(events=len(truth), missed=len(truth)-len(delays), delays_seconds=delays,
                normal_hours=hours, false_incidents=false, false_incidents_per_hour=false/hours if hours else None,
                false_windows=false_windows, false_windows_per_hour=false_windows/hours if hours else None,
                scored_windows=scored, scored_normal_windows=scored_normal, total_windows=len(rows))


def compare(folder, collection, baseline, output, seed=42):
    if output.exists():
        raise FileExistsError(output)
    parts = read_partitions(folder)
    manifest = json.loads((folder/'manifest.json').read_text())
    ref = json.loads((baseline/'report.json').read_text())
    detector = load_bundle(baseline/'bundle.json', ref['bundle_sha256'])['detector']
    digest = sha(folder/'manifest.json')
    if detector['dataset_manifest_sha256'] != digest or sha(collection/'collection.json') != manifest['collection_sha256']:
        raise ValueError('inconsistent experiment inputs')
    model, scale, training = fit(parts, detector['preprocessing'], seed)
    report = dict(training=training, budget_false_windows_per_normal_hour=BUDGET,
                  dataset_manifest_sha256=digest, methods={})
    for part in ('calibration', 'validation', 'test'):
        rows = timeline(collection, manifest, parts, part)
        normal = np.array([r['label'] == 'normal' for r in rows])
        groups = {g:manifest['groups'][g] for g in manifest['splits'][part]['groups']}
        for name, vector in predictions(rows, detector, model, scale).items():
            item = report['methods'].setdefault(name,{})
            if part == 'calibration':
                eligible = vector[normal & np.isfinite(vector)]
                if not len(eligible):
                    raise ValueError('empty calibration exposure')
                item['threshold'] = calibrate(eligible)
            item[part] = evaluate(rows, vector, item['threshold'], groups)
        if part == 'validation':
            # Only the two deployable models compete for promotion; the test stays descriptive.
            def rank(name):
                m = report['methods'][name]['validation']
                return (m['false_windows_per_hour'] > BUDGET, m['missed'], m['false_incidents_per_hour'],
                        m['false_windows_per_hour'], np.mean(m['delays_seconds']) if m['delays_seconds'] else float('inf'))
            report['working_model'] = min(('isolation_forest','gru'), key=rank)
    payload = dict(format=1, architecture='gru', features=FEATURES, feature_set_version=VERSION, history=HISTORY,
                   policy_version=POLICY, profile=detector['profile'], preprocessing=detector['preprocessing'],
                   residual_scale=scale.tolist(), dataset_manifest_sha256=digest, seed=seed,
                   threshold=report['methods']['gru']['threshold'], torch_version=str(torch.__version__),
                   weights={k:v.tolist() for k,v in model.state_dict().items()})
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        dest = Path(tmp)/'result'
        dest.mkdir()
        path = dest/'bundle.json'
        path.write_text(json.dumps(dict(model_id=model_id(payload),detector=payload), allow_nan=False,separators=(',',':')))
        checksum = sha(path)
        load_bundle(path, checksum)
        report.update(model_id=model_id(payload),bundle_sha256=checksum, baseline_model_id=ref['model_id'])
        (dest/'report.json').write_text(json.dumps(report,allow_nan=False,indent=2)+'\n')
        dest.rename(output)
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('dataset','collection','baseline','output'):
        parser.add_argument(name,type=Path)
    args = parser.parse_args()
    print(json.dumps(compare(args.dataset,args.collection,args.baseline,args.output),indent=2))
