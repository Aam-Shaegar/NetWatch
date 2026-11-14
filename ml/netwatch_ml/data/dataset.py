"""Audit live NetWatch runs, join observed intervals and export group-split Parquet."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import pyarrow as pa
import pyarrow.parquet as pq

from netwatch_ml.contracts import ROOT, validate
from netwatch_ml.data.splits import split_groups


def read_json(path):
    return json.loads(path.read_text())


def json_lines(path):
    with path.open() as stream:
        for line in stream:
            yield json.loads(line)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def label_window(window, truth, entity):
    start, end = int(window['window_start_ns']), int(window['window_end_ns'])
    if window['entity_type'] != 'destination_service' or window['entity_id'] != entity:
        raise ValueError('unexpected observation entity')
    quality = window['quality']
    if quality['coverage'] != 'complete' or any(quality[key] != 0 for key in
            ('capture_dropped', 'late_packets', 'state_evictions')):
        return 'incomplete'
    if any(start < right and end > left for left, right in truth.get('background_gaps', [])):
        return 'unobserved'
    if start < truth['start_ns'] or end > truth['end_ns']:
        return 'boundary'
    for event in truth['events']:
        if start >= event['start_ns'] and end <= event['end_ns']:
            return event['kind']
        if start < event['end_ns'] and end > event['start_ns']:
            return 'mixed'
    return 'normal'


def packet_count(capture, expression):
    # tcpdump uses libpcap independently of Go's decoder and window aggregation.
    with tempfile.TemporaryFile() as lines:
        subprocess.run(['tcpdump', '-nn', '-q', '-t', '-r', str(capture), expression],
                       stdout=lines, stderr=subprocess.PIPE, check=True, timeout=120)
        lines.seek(0)
        return sum(1 for _ in lines)


def read_run(folder, sensor, scratch):
    m = read_json(folder / 'manifest.json')
    capture = folder / 'live.pcap'
    if m['status'] != 'captured' or m['group_id'] != folder.name or digest(capture) != m['sha256']:
        raise ValueError(f'invalid capture manifest in {folder}')
    truth = read_json(folder / 'truth.json')
    required = ['main', 'background']
    if m['profile'] == 'flash-crowd':
        required += ['visitor1', 'visitor2']
    if truth['lanes'] != required or truth['end_ns'] <= truth['start_ns']:
        raise ValueError('invalid scenario timeline')
    truth['background_gaps'] = []
    events = truth['events']
    if len(events) != int(m['profile'] == 'pause') or any(
            e['kind'] != 'foreground_pause' or not truth['start_ns'] <= e['start_ns'] < e['end_ns'] <= truth['end_ns']
            for e in events):
        raise ValueError('invalid fault interval')
    requests = Counter()
    event = events[0] if events else None
    background_during_pause = 0
    lane_counts = {}
    for lane in required:
        path, size = ('/background', 32768) if lane == 'background' else ('/', 13)
        count = 0
        previous = truth['start_ns']
        first = last = None
        for req in json_lines(folder / (lane + '.jsonl')):
            if not previous <= req['start_ns'] <= req['end_ns'] <= truth['end_ns']:
                raise ValueError('invalid request timeline')
            # Background requests recur every ~2 s. A larger unexplained gap
            # breaks temporal continuity, including when the VM clock advances.
            if lane == 'background' and req['start_ns'] - previous > 6_000_000_000:
                truth['background_gaps'].append((previous, req['start_ns']))
            if lane == 'background' and req['end_ns'] - req['start_ns'] > 6_000_000_000:
                truth['background_gaps'].append((req['start_ns'], req['end_ns']))
            previous = req['end_ns']
            first = req['start_ns'] if first is None else first
            last = req['end_ns']
            if req['path'] != path or req['bytes'] != size:
                raise ValueError('unexpected HTTP response')
            if event and event['start_ns'] <= req['start_ns'] < event['end_ns']:
                if lane == 'main':
                    raise ValueError('foreground requests during pause')
                background_during_pause += 1
            count += 1
        if lane == 'background' and truth['end_ns'] - previous > 6_000_000_000:
            truth['background_gaps'].append((previous, truth['end_ns']))
        if count == 0:
            raise ValueError('missing workload lane')
        requests[path] += count
        lane_counts[lane] = dict(requests=count, first_request_ns=first, last_response_ns=last)
    if event and not background_during_pause:
        raise ValueError('background transfer absent during pause')
    if requests != Counter(m['target_requests']):
        raise ValueError('client and target HTTP counts differ')
    if packet_count(capture, 'tcp dst port 8080 and tcp[((tcp[12] & 0xf0) >> 2):4] = 0x47455420') != requests.total():
        raise ValueError('observed GET count differs from accepted requests')

    rows = list(json_lines(folder / 'live.jsonl'))
    if not rows:
        raise ValueError('empty capture')
    epoch = rows[0]['capture_epoch']
    replay = scratch / (folder.name + '.jsonl')
    subprocess.run([str(sensor), 'replay', '--input', str(capture), '--output', str(replay),
                    '--service', m['service'], '--epoch', epoch, '--sensor', rows[0]['sensor_id']],
                   check=True, capture_output=True, timeout=180)
    reference = {row['event_id']: row for row in json_lines(replay)}
    results = []
    totals = Counter()
    labels = Counter()
    seen = set()
    for row in rows:
        validate('window', row)
        identity = row['event_id']
        if identity in seen or row['capture_epoch'] != epoch or reference.get(identity, {}).get('features') != row['features']:
            raise ValueError('live/replay mismatch or duplicate window')
        seen.add(identity)
        label = label_window(row, truth, 'TCP/' + m['service'])
        labels[label] += 1
        totals.update({key: row['features'][key] for key in ('in_packets', 'out_packets')})
        results.append(dict(event_id=identity, group_id=m['group_id'], label=label, profile=m['profile'],
                            window_start_ns=int(row['window_start_ns']), entity_id=row['entity_id'],
                            **row['features']))
    stats = m['capture']
    if seen != reference.keys() or stats['records'] != totals.total() or stats['late_packets'] or any(
            stats['stats'][k] for k in ('dropped', 'interface_dropped')):
        raise ValueError('coverage or packet count mismatch')
    for key, direction in [('in_packets', 'dst'), ('out_packets', 'src')]:
        if totals[key] != packet_count(capture, 'tcp ' + direction + ' port 8080'):
            raise ValueError('directional count mismatch')
    if not labels['normal'] or (event and not labels['foreground_pause']):
        raise ValueError('no usable complete windows for scenario')
    sources = ['manifest.json', 'truth.json', 'live.jsonl'] + [lane + '.jsonl' for lane in required]
    return m, results, dict(labels=labels, packets=totals.total(), requests=dict(requests),
                            source_hashes={name: digest(folder / name) for name in sources},
                            lanes=lane_counts, observed_start_ns=truth['start_ns'],
                            observed_end_ns=truth['end_ns'], events=events,
                            background_gaps=truth['background_gaps'],
                            achieved_rps=requests.total() * 1e9 / (truth['end_ns'] - truth['start_ns']),
                            sha256=m['sha256'], profile=m['profile'], features=len(rows[0]['features']))


def build(collection, destination, sensor):
    if destination.exists():
        raise FileExistsError(destination)
    index = read_json(collection / 'collection.json')
    groups = index['groups']
    if len(set(groups)) != len(groups) or any(Path(g).name != g or not g.startswith('nw-') for g in groups):
        raise ValueError('invalid group IDs')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as staging:
        scratch = Path(staging)
        output = scratch / 'dataset'
        output.mkdir()
        report = {'schema_version': 1, 'feature_set_version': 'traffic-v1', 'groups': {}, 'splits': {}}
        records, rows = [], {}
        report['collection'] = collection.name
        report['config'] = index['config']
        report['collection_sha256'] = digest(collection / 'collection.json')
        for group in groups:
            m, rows[group], report['groups'][group] = read_run(collection / group, sensor, scratch)
            for name, expected in m['provenance']['sources'].items():
                source = (collection / 'sources' / name).resolve()
                if not source.is_relative_to((collection / 'sources').resolve()) or digest(source) != expected:
                    raise ValueError('scenario source snapshot mismatch')
            records.append(m)
        if len({r['sha256'] for r in records}) != len(records):
            raise ValueError('duplicate capture')
        normal = [r for r in records if r['profile'] != 'pause']
        partitions = split_groups(normal, index['config']['seed'])
        faults = [r for r in records if r['profile'] == 'pause']
        if len(faults) != 2:
            raise ValueError('expected two independent fault runs')
        partitions['validation'].append(faults[0])
        partitions['test'].append(faults[1])
        features = sorted(read_json(ROOT / 'contracts/window.schema.json')['properties']['features']['required'])
        report['feature_columns'] = features
        seen_ids, fingerprints = set(), {}
        for name, manifests in partitions.items():
            selected = []
            for m in manifests:
                report['groups'][m['group_id']]['split'] = name
                for row in rows[m['group_id']]:
                    if row['event_id'] in seen_ids:
                        raise ValueError('duplicate event across dataset')
                    seen_ids.add(row['event_id'])
                    if row['label'] not in {'normal', 'foreground_pause'}:
                        continue
                    vector = tuple(row[f] for f in features)
                    if fingerprints.setdefault(vector, name) != name:
                        raise ValueError('identical feature record in different partitions')
                    selected.append(row)
            if not selected:
                raise ValueError('empty partition')
            floats = {'syn_fraction', 'rst_fraction', 'mean_packet_size', 'std_packet_size',
                      'mean_interarrival_seconds', 'std_interarrival_seconds'}
            schema = pa.schema([(k, pa.string()) for k in ('event_id', 'group_id', 'label', 'profile')] +
                               [('window_start_ns', pa.int64()), ('entity_id', pa.string())] +
                               [(f, pa.float64() if f in floats else pa.int64()) for f in features])
            path = output / (name + '.parquet')
            pq.write_table(pa.Table.from_pylist(selected, schema=schema), path)
            report['splits'][name] = dict(groups=[m['group_id'] for m in manifests],
                labels=dict(Counter(row['label'] for row in selected)), rows=len(selected), sha256=digest(path))
        (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        output.rename(destination)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('collection', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        sensor = Path(tmp) / 'netwatch-sensor'
        subprocess.run(['go', 'build', '-o', str(sensor), './cmd/netwatch-sensor'], cwd=ROOT, check=True)
        report = build(args.collection, args.output, sensor)
    for name, part in report['splits'].items():
        print(name, len(part['groups']), 'runs', part['labels'])


if __name__ == '__main__':
    main()
