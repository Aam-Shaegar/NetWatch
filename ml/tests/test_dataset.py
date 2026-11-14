import pytest

from netwatch_ml.data.dataset import label_window


def row(start, end):
    return dict(entity_type='destination_service', entity_id='TCP/service:8080',
                window_start_ns=str(start), window_end_ns=str(end),
                quality=dict(coverage='complete', capture_dropped=0, late_packets=0, state_evictions=0))


truth = dict(start_ns=1, end_ns=21, events=[dict(start_ns=7, end_ns=14, kind='foreground_pause')])


@pytest.mark.parametrize('start,end,expected', [(0, 5, 'boundary'), (2, 7, 'normal'),
    (5, 10, 'mixed'), (7, 12, 'foreground_pause'), (9, 14, 'foreground_pause'),
    (10, 15, 'mixed'), (14, 19, 'normal'), (17, 22, 'boundary')])
def test_half_open_observed_intervals(start, end, expected):
    assert label_window(row(start, end), truth, 'TCP/service:8080') == expected


def test_unknown_loss_or_other_entity_cannot_be_labelled_normal():
    window = row(2, 7)
    window['quality']['capture_dropped'] = None
    assert label_window(window, truth, 'TCP/service:8080') == 'incomplete'
    with pytest.raises(ValueError, match='entity'):
        label_window(window, truth, 'TCP/other:8080')


def test_missing_background_evidence_excludes_intersecting_windows():
    with_gap = dict(truth, background_gaps=[(4, 8)])
    assert label_window(row(2, 7), with_gap, 'TCP/service:8080') == 'unobserved'
    assert label_window(row(8, 13), with_gap, 'TCP/service:8080') == 'foreground_pause'


@pytest.mark.parametrize('duplicate', [False, True])
def test_export_publishes_whole_groups_and_rejects_feature_leakage(tmp_path, monkeypatch, duplicate):
    import json
    import pyarrow.parquet as pq
    from netwatch_ml.contracts import ROOT
    from netwatch_ml.data import dataset

    groups = [f'nw-{i}' for i in range(12)]
    (tmp_path / 'collection.json').write_text(json.dumps(dict(groups=groups, config={'seed': 42})))
    features = json.loads((ROOT / 'contracts/examples/window.valid.json').read_text())['features']

    def checked_run(folder, sensor, scratch):
        group = folder.name
        index = groups.index(group)
        fault = index >= 10
        manifest = dict(group_id=group, sha256=str(index), profile='pause' if fault else 'stable',
                        provenance={'sources': {}})
        record = dict(features, event_id=group, group_id=group, label='foreground_pause' if fault else 'normal',
                      profile=manifest['profile'], window_start_ns=0, entity_id='lab',
                      in_packets=1 if duplicate else index)
        return manifest, [record], {}

    monkeypatch.setattr(dataset, 'read_run', checked_run)
    destination = tmp_path / 'export'
    if duplicate:
        with pytest.raises(ValueError, match='identical feature record'):
            dataset.build(tmp_path, destination, None)
        assert not destination.exists()
        return
    report = dataset.build(tmp_path, destination, None)
    assert set(report['feature_columns']) == set(features)
    seen = set()
    for split, part in report['splits'].items():
        records = pq.read_table(destination / (split + '.parquet')).to_pylist()
        assert len(records) == part['rows']
        assert {r['group_id'] for r in records} == set(part['groups'])
        assert not seen.intersection(part['groups'])
        seen.update(part['groups'])
        assert sum(r['label'] == 'foreground_pause' for r in records) == int(split in {'validation', 'test'})
    assert seen == set(groups)
    with pytest.raises(FileExistsError):
        dataset.build(tmp_path, destination, None)
