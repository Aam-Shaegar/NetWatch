import json
import logging
import os
import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from jsonschema import ValidationError

from netwatch_ml.contracts import validate
from netwatch_ml.security import assess
from netwatch_ml.models.detector import POLICY, load_bundle, predict_window
from netwatch_ml.v1 import model as v1_model


def request_fields(request):
    request_id = request.headers.get("x-request-id", "")
    if re.fullmatch(r"[a-zA-Z0-9._:-]{1,128}", request_id):
        return {"request_id": request_id}
    return {}


def create_app(bundle_path=None, checksum=None, service_entities=(), expected_model_id=None,
               expected_feature_set=None, projection_policy=POLICY,
               v1_bundle_path=None, v1_checksum=None):
    app = FastAPI(title='NetWatch ML', version='0.3.0')
    log = logging.getLogger(__name__)
    bundle = None
    if bundle_path:
        try:
            if projection_policy not in (POLICY, 'v2'):
                raise ValueError('unsupported projection policy')
            candidate = load_bundle(Path(bundle_path), checksum)
            if expected_model_id and candidate['model_id'] != expected_model_id:
                raise ValueError('unexpected model identifier')
            if expected_feature_set and candidate['detector']['feature_set_version'] != expected_feature_set:
                raise ValueError('model and configured sensor require different feature sets')
            bundle = candidate
            log.info('model_loaded', extra={'fields': {'model_id': bundle['model_id']}})
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            log.error('model_validation_failed')
    elif not v1_bundle_path:
        log.warning('no_validated_model')

    v1_bundle = None
    if v1_bundle_path:
        try:
            v1_bundle = v1_model.load_bundle(v1_bundle_path, v1_checksum, expected_model_id)
            log.info('v1_model_loaded', extra={'fields': {'model_id': v1_bundle['model_id']}})
        except (OSError, ValueError, KeyError, TypeError, AttributeError, ImportError, EOFError):
            log.error('v1_model_validation_failed')

    @app.get('/health/live')
    def live():
        return {'status': 'alive'}

    @app.get('/health/ready')
    def ready():
        selected = v1_bundle if v1_bundle_path else bundle
        if selected is None:
            return JSONResponse(status_code=503, content={'status': 'not_ready', 'reason': 'no_validated_model'})
        return {'status': 'ready', 'model_id': selected['model_id'], 'policy_version': projection_policy}

    @app.post('/v1/security/assess')
    async def security_assessment(request: Request):
        raw = bytearray()
        async for block in request.stream():
            if len(raw) + len(block) > 65536:
                return JSONResponse(status_code=413, content={'error': 'observation_too_large'})
            raw.extend(block)
        try:
            assessment = assess(json.loads(raw))
            log.debug('security_assessment_completed', extra={'fields': {
                **request_fields(request), 'ruleset': assessment['ruleset'],
            }})
            return assessment
        except (ValidationError, ValueError, UnicodeError, RecursionError, OverflowError):
            return JSONResponse(status_code=422, content={'error': 'invalid_security_observation'})

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
            if body['model_id'] != bundle['model_id'] or body['policy_version'] != projection_policy:
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
        results = []
        for window in body['windows']:
            if service_entities and window['entity_id'] not in service_entities:
                results.append(dict(schema_version=1, event_id=window['event_id'],
                    model_id=bundle['model_id'], feature_set_version=window['feature_set_version'],
                    status='insufficient_data', unavailable_reason='outside_model_scope', score=None, threshold=None))
            else:
                results.append(predict_window(window, bundle, histories.get(window['event_id'], ())))
        log.debug('prediction_completed', extra={'fields': {
            **request_fields(request), 'model_id': bundle['model_id'],
            'event_ids': [window['event_id'] for window in body['windows']],
        }})
        return {'schema_version': 1, 'predictions': results}

    @app.post('/v1/detect')
    async def detect(request: Request):
        if v1_bundle is None:
            return JSONResponse(status_code=503, content={'error': 'no_validated_model'})
        raw = bytearray()
        async for block in request.stream():
            if len(raw) + len(block) > 65536:
                return JSONResponse(status_code=413, content={'error': 'body_too_large'})
            raw.extend(block)
        try:
            body = json.loads(raw)
            if (not isinstance(body, dict) or body.keys() != {'schema_version', 'model_id', 'window'}
                    or type(body['schema_version']) is not int or body['schema_version'] != 1
                    or not isinstance(body['model_id'], str)):
                raise ValueError()
            window = validate('window', body['window'])
            if window['feature_set_version'] != v1_model.FEATURE_SET:
                raise ValueError()
        except (ValidationError, UnicodeError, ValueError, TypeError, OverflowError, RecursionError):
            return JSONResponse(status_code=422, content={'error': 'invalid_inference_request'})
        if body['model_id'] != v1_bundle['model_id']:
            return JSONResponse(status_code=409, content={'error': 'incompatible_model'})
        try:
            return await run_in_threadpool(v1_model.predict, window, v1_bundle)
        except (ValueError, TypeError, ArithmeticError):
            log.error('v1_prediction_failed', extra={'fields': request_fields(request)})
            return JSONResponse(status_code=503, content={'error': 'prediction_unavailable'})

    return app


SYSTEM_ENTITIES = frozenset(filter(None, map(str.strip, os.getenv('NETWATCH_SERVICE_MODEL_ENTITIES', '').split(','))))
app = create_app(
    os.getenv('NETWATCH_MODEL_BUNDLE'),
    os.getenv('NETWATCH_MODEL_SHA256'),
    SYSTEM_ENTITIES,
    os.getenv('NETWATCH_MODEL_ID'),
    os.getenv('NETWATCH_FEATURE_SET_VERSION'),
    os.getenv('NETWATCH_POLICY_VERSION', POLICY),
    os.getenv('NETWATCH_V1_MODEL_BUNDLE'),
    os.getenv('NETWATCH_V1_MODEL_SHA256'),
)
