import json

import numpy as np
import torch
from fastapi.testclient import TestClient

from netwatch_ml.contracts import ROOT
from netwatch_ml.models.detector import FEATURES, WIDTH, model_id
from netwatch_ml.models.gru import GRUForecast, HISTORY, STEP, residuals, sequences
from netwatch_ml.serving.app import create_app
from netwatch_ml.training.baselines import sha
from netwatch_ml.training.forecast import evaluate, fit


def test_causal_sequences_and_masks():
    rows = [dict(group_id=g, entity_id=e, window_start_ns=i*STEP)
            for g in ('one', 'two') for i in [*range(14), *range(15, 27)] for e in ('a','b')]
    histories, targets = sequences(rows)
    assert len(targets) == 8
    for past, target in zip(histories, targets):
        assert target not in past
        for offset, idx in enumerate(past):
            assert rows[idx] == dict(rows[target],window_start_ns=rows[target]['window_start_ns']-(12-offset)*STEP)
    values = torch.zeros(1, 2*WIDTH)
    values[0, WIDTH] = 1
    assert torch.isnan(residuals(torch.ones(1, WIDTH), values)[0,0])


def test_fit_reproduces_and_ignores_test():
    rows = [dict.fromkeys(FEATURES, float(i)) | dict(group_id='g', entity_id='e',
            window_start_ns=i*STEP, label='normal') for i in range(18)]
    params = {'median':[0]*WIDTH,'scale':[1]*WIDTH}
    parts = {'train':rows,'validation':rows}
    one, scale, history = fit(parts, params, 42)
    two, scale2, history2 = fit(dict(parts,test=None), params, 42)
    assert history == history2
    torch.testing.assert_close(scale, scale2)
    for a,b in zip(one.parameters(),two.parameters()):
        torch.testing.assert_close(a,b,atol=0,rtol=0)


def test_sequence_serving_and_batch_parity(tmp_path):
    model = GRUForecast().eval()
    x = torch.randn(3,HISTORY,2*WIDTH)
    with torch.no_grad():
        torch.testing.assert_close(model(x), torch.cat([model(v[None]) for v in x]))
    params = dict(median=[0]*WIDTH,scale=[1]*WIDTH)
    payload = dict(format=1, architecture='gru',features=FEATURES,feature_set_version='traffic-v1',
                   history=12, policy_version='v1',profile='tcp-service-8080-5s',preprocessing=params,
                   residual_scale=[1]*WIDTH,threshold=1,weights={k:v.tolist() for k,v in model.state_dict().items()})
    ident = model_id(payload)
    path = tmp_path/'bundle.json'
    path.write_text(json.dumps(dict(model_id=ident, detector=payload)))
    client = TestClient(create_app(path,sha(path)))
    w = json.loads((ROOT/'contracts/examples/window.valid.json').read_text())
    w.update(entity_type='destination_service',entity_id='TCP/service:8080')
    w['quality']['capture_dropped'] = 0
    windows = [dict(w,event_id=str(i),window_start_ns=str(i*STEP), window_end_ns=str((i+1)*STEP))
               for i in range(14)]
    def post(targets, past):
        return client.post('/v1/predict',json=dict(schema_version=1,model_id=ident,policy_version='v1',
                                                    windows=targets,histories=past)).json()['predictions']
    single = post([windows[12]],{'12':windows[:12]})[0]
    assert single['score'] is not None
    batch = post(windows[12:],{'12':windows[:12],'13':windows[1:13]})
    assert batch == [single,post([windows[13]],{'13':windows[1:13]})[0]]
    for history in (windows[:11], [dict(windows[0],capture_epoch='other'),*windows[1:12]],
                    [dict(windows[0],window_end_ns='1'),*windows[1:12]]):
        assert post([windows[12]],{'12':history})[0]['status']=='warming_up'


def test_incident_metrics_count_openings_and_delays():
    rows = [dict(group_id='a',entity_id='one',window_start_ns=i*STEP,label='normal' if i<6 else 'foreground_pause')
            for i in range(10)]
    groups = {'a':{'events':[dict(start_ns=6*STEP,end_ns=10*STEP)]}}
    m = evaluate(rows,np.array([0,2,2,0,0,0,0,2,2,2]),1,groups)
    assert (m['false_incidents'],m['missed'],m['delays_seconds'])==(1,0,[15])
