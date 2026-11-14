import json
import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jsonschema import ValidationError

from netwatch_ml.contracts import validate
from netwatch_ml.models.detector import POLICY, load_bundle, predict_window


def create_app(bundle_path=None, checksum=None):
    app = FastAPI(title='NetWatch ML', version='0.3.0')
    bundle = None
    if bundle_path:
        try:
            bundle = load_bundle(Path(bundle_path), checksum)
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            logging.getLogger(__name__).error('Configured detector failed validation')

    @app.get('/health/live')
    def live():
        return {'status': 'alive'}

    @app.get('/health/ready')
    def ready():
        if bundle is None:
            return JSONResponse(status_code=503, content={'status': 'not_ready', 'reason': 'no_validated_model'})
        return {'status': 'ready', 'model_id': bundle['model_id']}

    @app.post('/v1/predict')
    async def predict(request: Request):
        if bundle is None:
            return JSONResponse(status_code=503, content={'error': 'no_validated_model'})
        raw = bytearray()
        async for block in request.stream():
            if len(raw) + len(block) > 2 << 20:
                return JSONResponse(status_code=413, content={'error': 'body_too_large'})
            raw.extend(block)
        try:
            body = json.loads(raw)
            if (not isinstance(body, dict) or set(body) - {'histories'} != {'schema_version', 'model_id', 'policy_version', 'windows'}
                    or type(body['schema_version']) is not int or body['schema_version'] != 1
                    or not isinstance(body['windows'], list) or not 1 <= len(body['windows']) <= 100):
                raise ValueError()
            if body['model_id'] != bundle['model_id'] or body['policy_version'] != POLICY:
                return JSONResponse(status_code=409, content={'error': 'incompatible_model_or_policy'})
            ids = set()
            for window in body['windows']:
                validate('window', window)
                if window['event_id'] in ids:
                    raise ValueError()
                ids.add(window['event_id'])
            histories = body.get('histories', {})
            if not isinstance(histories, dict) or histories.keys() - ids:
                raise ValueError()
            for past in histories.values():
                if not isinstance(past, list) or len(past) > 12:
                    raise ValueError()
                for previous in past:
                    validate('window', previous)
        except (ValidationError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            return JSONResponse(status_code=422, content={'error': 'invalid_inference_request'})
        return {'schema_version': 1, 'predictions': [predict_window(w, bundle, histories.get(w['event_id'], ())) for w in body['windows']]}

    return app


app = create_app(os.getenv('NETWATCH_MODEL_BUNDLE'), os.getenv('NETWATCH_MODEL_SHA256'))
