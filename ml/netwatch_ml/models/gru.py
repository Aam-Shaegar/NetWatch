"""Causal five-second traffic forecasting on CPU."""
from collections import deque

import numpy as np
import torch
from torch import nn

from netwatch_ml.models.detector import WIDTH, matrix, transform, supported_window

HISTORY = 12
STEP = 5_000_000_000


class GRUForecast(nn.Module):
    def __init__(self):
        super().__init__()
        self.gru = nn.GRU(2 * WIDTH, 64, batch_first=True)
        self.head = nn.Linear(64, WIDTH)

    def forward(self, past):
        _, hidden = self.gru(past)
        return self.head(hidden[-1])


def sequences(rows):
    """Return history and target indices; each stream progresses independently."""
    streams = {}
    histories, targets = [], []
    for i, row in enumerate(rows):
        key = row['group_id'], row['entity_id']
        past = streams.setdefault(key, deque(maxlen=HISTORY))
        if past and rows[past[-1]]['window_start_ns'] + STEP != row['window_start_ns']:
            past.clear()
        if len(past) == HISTORY:
            histories.append(list(past))
            targets.append(i)
        past.append(i)
    return np.asarray(histories, dtype=int).reshape(-1, HISTORY), np.asarray(targets, dtype=int)


def residuals(output, target):
    return (output - target[:, :WIDTH]).abs().masked_fill(target[:, WIDTH:].bool(), torch.nan)


def scores(errors, scale):
    return torch.nanmean(errors / scale, dim=1)


def unpack(payload):
    model = GRUForecast()
    weights = payload['weights']
    if weights.keys() != model.state_dict().keys():
        raise ValueError('unexpected GRU parameters')
    state = {}
    for key, ref in model.state_dict().items():
        value = torch.tensor(weights[key], dtype=ref.dtype)
        if value.shape != ref.shape or not torch.isfinite(value).all():
            raise ValueError('invalid GRU tensor')
        state[key] = value
    model.load_state_dict(state)
    scale = torch.tensor(payload['residual_scale'], dtype=torch.float32)
    if scale.shape != (WIDTH,) or not torch.isfinite(scale).all() or torch.any(scale <= 0):
        raise ValueError('invalid GRU residual scale')
    return model.eval(), scale


@torch.inference_mode()
def predict_sequence(window, history, bundle):
    result = dict(schema_version=1, event_id=window['event_id'], model_id=bundle['model_id'],
                  feature_set_version='traffic-v1', status='insufficient_data', score=None, threshold=None)
    if not supported_window(window):
        return result
    key = ('sensor_id', 'capture_epoch', 'entity_type', 'entity_id')
    ordered = [*history, window]
    if len(history) != HISTORY or any(
        not supported_window(left) or any(left[k] != window[k] for k in key)
        or left['window_end_ns'] != right['window_start_ns']
        for left, right in zip(ordered, ordered[1:])
    ):
        result['status'] = 'warming_up'
        return result
    payload = bundle['detector']
    values = torch.tensor(transform(matrix([w['features'] for w in ordered]), payload['preprocessing']),
                          dtype=torch.float32)
    model, scale = bundle['runtime']
    score = scores(residuals(model(values[:-1].unsqueeze(0)), values[-1:]), scale).item()
    if np.isfinite(score):
        threshold = payload['threshold']
        result.update(score=score, threshold=threshold, status='anomalous' if score > threshold else 'normal')
    return result
