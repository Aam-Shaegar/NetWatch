import hashlib
import json

from fastapi.testclient import TestClient
import pytest

from netwatch_ml.contracts import ROOT, validate
from netwatch_ml.models.detector import FEATURES, FEATURE_SETS, VERSION, LIFECYCLE_VERSION, load_bundle
from netwatch_ml.serving.app import create_app
from netwatch_ml.training.profiled import train


@pytest.fixture(params=[VERSION, LIFECYCLE_VERSION])
def captures(tmp_path, request):
    binding = dict(sensor_id='sensor-a', entity_id='TCP/192.0.2.10:443')
    example = json.loads((ROOT / 'contracts/examples/window.valid.json').read_text())
    version = request.param
    example['feature_set_version'] = version
    for name in set(FEATURE_SETS[version]) - set(FEATURES):
        example['features'][name] = 0.2
    groups = {}
    for day, part in enumerate(('train', 'calibration'), start=1):
        records = []
        for i in range(10):
            start = int(example['window_start_ns']) + (day * 100 + i) * 5_000_000_000
            records.append(dict(example, **binding, event_id=f'{part}-{i}',
                                capture_epoch=part, entity_type='destination_service',
                                window_start_ns=str(start), window_end_ns=str(start + 5_000_000_000),
                                features=dict(example['features'], out_packets=i + 1),
                                quality=dict(example['quality'], capture_dropped=0)))
        data = ''.join(json.dumps(row) + '\n' for row in records).encode()
        path = tmp_path / f'{part}.jsonl'
        path.write_bytes(data)
        groups[part] = [dict(label='normal', source_sha256=str(day) * 64, windows=path.name,
                             windows_sha256=hashlib.sha256(data).hexdigest())]
    manifest = dict(schema_version=1, feature_set_version=version, binding=binding, captures=groups)
    return tmp_path / 'manifest.json', manifest, records[0]


def test_profiled_training_and_serving(captures, tmp_path):
    manifest_path, manifest, window = captures
    manifest_path.write_text(json.dumps(manifest))
    output = tmp_path / 'result'
    report = train(manifest_path, output)
    artifact = output / 'bundle.json'
    assert report['calibration_false_windows'] == 0
    assert load_bundle(artifact, report['bundle_sha256'])['detector']['binding'] == manifest['binding']
    client = TestClient(create_app(artifact, report['bundle_sha256']))
    other_version = VERSION if report['feature_set_version'] == LIFECYCLE_VERSION else LIFECYCLE_VERSION
    assert TestClient(create_app(artifact, report['bundle_sha256'], expected_feature_set=other_version)
                      ).get('/health/ready').status_code == 503
    windows = [
        window,
        dict(window, event_id='other-sensor', sensor_id='sensor-b'),
        dict(window, event_id='other-port', entity_id='TCP/192.0.2.10:8443'),
        dict(window, event_id='unknown-loss', quality=dict(window['quality'], capture_dropped=None)),
        dict(window, event_id='other-version', feature_set_version=other_version,
             features={key: window['features'].get(key) for key in FEATURE_SETS[other_version]}),
    ]
    response = client.post('/v1/predict', json=dict(schema_version=1, policy_version='v1',
                                                   model_id=report['model_id'], windows=windows))
    assert response.status_code == 200
    predictions = [validate('prediction', row) for row in response.json()['predictions']]
    assert [row['status'] for row in predictions] == ['normal'] + ['insufficient_data'] * 4
    assert predictions[-1]['feature_set_version'] == other_version
    assert [row['unavailable_reason'] for row in predictions[1:]] == [
        'outside_model_scope', 'outside_model_scope', 'unverified_capture_quality', 'feature_set_mismatch'
    ]
    assert 'classification' not in predictions[0]
    with pytest.raises(FileExistsError):
        train(manifest_path, output)


def test_profiled_rejects_reused_capture(captures, tmp_path):
    manifest_path, manifest, _ = captures
    groups = manifest['captures']
    groups['calibration'][0]['source_sha256'] = groups['train'][0]['source_sha256']
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='distinct source'):
        train(manifest_path, tmp_path / 'result')
