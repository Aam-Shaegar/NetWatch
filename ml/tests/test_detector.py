import json
from pathlib import Path

from fastapi.testclient import TestClient
import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from netwatch_ml.contracts import ROOT, validate
from netwatch_ml.models.detector import FEATURES
from netwatch_ml.serving.app import create_app
from netwatch_ml.training.baselines import PARTS, calibrate, ewma_scores, read_partitions, sha, train


@pytest.fixture
def dataset(tmp_path):
    fixture = json.loads((ROOT / 'contracts/examples/window.valid.json').read_text())
    manifest = dict(schema_version=1, feature_set_version='traffic-v1', feature_columns=FEATURES, splits={})
    for part in PARTS:
        records = [dict(fixture['features'], group_id=part, entity_id='TCP/service:8080',
                        window_start_ns=i * 5_000_000_000, event_id=f'{part}-{i}', label='normal',
                        out_packets=i + 1) for i in range(12)]
        path = tmp_path / (part + '.parquet')
        pq.write_table(pa.Table.from_pylist(records), path)
        manifest['splits'][part] = dict(sha256=sha(path), groups=[part], labels={'normal': 12}, rows=12)
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    return tmp_path


def test_training_and_scored_http_batch(dataset):
    output = dataset / 'trained'
    report = train(dataset, output)
    bundle = output / 'bundle.json'
    client = TestClient(create_app(bundle, report['bundle_sha256']))
    assert client.get('/health/ready').json()['model_id'] == report['model_id']
    window = json.loads((ROOT / 'contracts/examples/window.valid.json').read_text())
    window.update(entity_type='destination_service', entity_id='TCP/service:8080')
    window['quality']['capture_dropped'] = 0
    partial = dict(window, event_id='partial', quality=dict(window['quality'], coverage='partial'))
    request = dict(schema_version=1, model_id=report['model_id'], policy_version='v1', windows=[window, partial])
    results = client.post('/v1/predict', json=request).json()['predictions']
    for result in results:
        validate('prediction', result)
    assert results[0]['score'] is not None
    assert results[1]['status'] == 'insufficient_data' and results[1]['score'] is None
    assert client.post('/v1/predict', json=dict(request, windows=[window, window])).status_code == 422
    assert client.post('/v1/predict', json=dict(request, model_id='different')).status_code == 409
    assert TestClient(create_app(bundle, '0' * 64)).get('/health/ready').status_code == 503


def test_reject_dataset_drift(dataset):
    manifest = dataset / 'manifest.json'
    value = json.loads(manifest.read_text())
    value['feature_set_version'] = 'other'
    manifest.write_text(json.dumps(value))
    with pytest.raises(ValueError, match='incompatible'):
        read_partitions(dataset)
    value['feature_set_version'] = 'traffic-v1'
    manifest.write_text(json.dumps(value))
    with (dataset / 'train.parquet').open('ab') as stream:
        stream.write(b'X')
    with pytest.raises(ValueError, match='checksum'):
        read_partitions(dataset)


def test_causal_reset_and_tied_calibration():
    rows = [dict(entity_id='one', group_id=g, window_start_ns=t * 5_000_000_000)
            for g, t in [('a', 0), ('a', 1), ('a', 3), ('b', 4)]]
    assert ewma_scores(rows, np.full((4, 1), 10.)).tolist() == [10., 8., 10., 10.]
    assert calibrate(np.array([1., 2., 2.])) == 2.
