"""Run API/store/worker integration tests against an isolated real PostgreSQL."""
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import urllib.request
import urllib.error
import subprocess
import time


def main(window_path=None, model_config=None, journal=None):
    root = Path(__file__).resolve().parents[1]
    name = f'netwatch-server-test-{time.time_ns()}'
    password = secrets.token_hex(24)
    env = dict(os.environ, POSTGRES_PASSWORD=password)
    def run(args, **kwargs):
        return subprocess.run(args, cwd=root, env=env, text=True, check=True, **kwargs)
    try:
        run(['docker', 'run', '-d', '--rm', '--name', name,
             '-e', 'POSTGRES_PASSWORD', '-e', 'POSTGRES_DB=netwatch_test',
             '-p', '127.0.0.1::5432', 'postgres:17.7-alpine'], capture_output=True)
        for _ in range(60):
            result = subprocess.run(['docker', 'exec', name, 'pg_isready', '-U', 'postgres',
                                     '-d', 'netwatch_test'], capture_output=True, timeout=5)
            if result.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError('test PostgreSQL did not become ready')
        address = json.loads(run(['docker', 'inspect', name], capture_output=True).stdout)[0]
        port = address['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort']
        env['NETWATCH_TEST_DATABASE_URL'] = f'postgres://postgres:{password}@127.0.0.1:{port}/netwatch_test?sslmode=disable'
        if window_path is None:
            run(['go', 'test', '-race', '-count=1', '-timeout', '180s', '-v', './internal/pipeline'], timeout=240)
        return native_smoke(root, name, env, run, window_path, model_config, journal)
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True, timeout=30)


def native_smoke(root, container, env, run, window_path, model_config, journal):
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]
    api_port, ml_port = port(), port()
    secret = secrets.token_hex(32)
    if window_path is None:
        window = json.loads((root / 'contracts/examples/window.valid.json').read_text())
        window.update(sensor_id='smoke', event_id='smoke-window')
        windows = [window]
    else:
        windows = [json.loads(line) for line in window_path.read_text().splitlines()]
    scope = windows[0]['sensor_id']
    native_env = dict(env, NETWATCH_DATABASE_URL=env['NETWATCH_TEST_DATABASE_URL'],
                      NETWATCH_LISTEN=f'127.0.0.1:{api_port}',
                      NETWATCH_SENSOR_TOKENS=json.dumps({scope: secret}),
                      NETWATCH_SENSOR_TOKEN=secret, NETWATCH_MODEL_ID='pending-model',
                      NETWATCH_ML_ENDPOINT=f'http://127.0.0.1:{ml_port}/v1/predict')
    for key in ('NETWATCH_MODEL_BUNDLE', 'NETWATCH_MODEL_SHA256'):
        native_env.pop(key, None)
    if model_config:
        native_env.update(model_config)
    expected_ready = 200 if model_config else 503
    def get(url, token=None):
        request = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'} if token else {})
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)
    children = []
    with tempfile.TemporaryDirectory(prefix='netwatch-server-') as folder:
        temp = Path(folder)
        with (temp / 'process.log').open('w+') as log:
            def execute(args):
                subprocess.run(args, cwd=root, env=native_env, check=True, timeout=120,
                               stdout=log, stderr=log)
            def launch(args):
                child = subprocess.Popen(args, cwd=root, env=native_env, stdout=log, stderr=log)
                children.append(child)
                return child
            try:
                run(['go', 'build', '-o', str(temp) + '/', './cmd/...'], timeout=120)
                execute([str(temp / 'netwatch-api'), '--migrate-only'])
                api_process = launch([str(temp / 'netwatch-api')])
                ml_command = [str(root / 'ml/.venv/bin/python'), '-m', 'uvicorn',
                        'netwatch_ml.serving.app:app', '--host', '127.0.0.1', '--port', str(ml_port)]
                ml_process = launch(ml_command)
                for _ in range(60):
                    try:
                        if get(f'http://127.0.0.1:{api_port}/health/ready')[0] == 200 and get(f'http://127.0.0.1:{ml_port}/health/ready')[0] == expected_ready:
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError('native API/ML startup failed')
                (temp / 'window.jsonl').write_text(''.join(json.dumps(w) + '\n' for w in windows))
                execute([str(temp / 'netwatch-sensor'), 'enqueue', '--input', str(temp / 'window.jsonl'), '--spool', str(temp / 'spool')])
                execute([str(temp / 'netwatch-sensor'), 'send', '--spool', str(temp / 'spool'), '--endpoint', f'http://127.0.0.1:{api_port}/v1/windows', '--once'])
                stored = run(['docker', 'exec', container, 'psql', '-U', 'postgres', '-d', 'netwatch_test',
                              '-At', '-c', 'SELECT event_id FROM inference_jobs'], capture_output=True)
                if set(stored.stdout.splitlines()) != {w['event_id'] for w in windows}:
                    raise RuntimeError('persisted jobs differ from submitted windows')
                worker_process = launch([str(temp / 'netwatch-worker')])
                if journal:
                    def restart():
                        for process in (worker_process, api_process, ml_process):
                            process.terminate()
                            process.wait(timeout=10)
                        run(['docker','restart',container], capture_output=True, timeout=30)
                        for _ in range(80):
                            ready=subprocess.run(['docker','exec',container,'pg_isready','-U','postgres'],
                                                 capture_output=True,timeout=5)
                            if ready.returncode==0:
                                break
                            time.sleep(.2)
                        exposed = run(['docker','port',container,'5432/tcp'], capture_output=True).stdout.strip()
                        port = exposed.rsplit(':', 1)[1]
                        native_env['NETWATCH_DATABASE_URL'] = f"postgres://postgres:{env['POSTGRES_PASSWORD']}@127.0.0.1:{port}/netwatch_test?sslmode=disable"
                        launch(ml_command)
                        launch([str(temp / 'netwatch-api')])
                        launch([str(temp / 'netwatch-worker')])
                    return journal(get, f'http://127.0.0.1:{api_port}', restart)
                if model_config:
                    for _ in range(100):
                        status, body = get(f"http://127.0.0.1:{api_port}/v1/predictions/{windows[0]['event_id']}", secret)
                        if status == 200 and body['predictions']:
                            prediction = body['predictions'][0]['prediction']
                            if (prediction['event_id'] != windows[0]['event_id'] or
                                prediction['model_id'] != model_config['NETWATCH_MODEL_ID'] or
                                prediction['status'] not in ('normal', 'anomalous') or
                                prediction['score'] is None or prediction['threshold'] is None):
                                raise RuntimeError('persisted model prediction is invalid')
                            print(json.dumps(prediction), flush=True)
                            return prediction
                        time.sleep(.1)
                    raise RuntimeError('trained model prediction did not reach PostgreSQL')
                for _ in range(60):
                    result = run(['docker', 'exec', container, 'psql', '-U', 'postgres', '-d', 'netwatch_test', '-At', '-c',
                                  "SELECT max(last_error) FROM inference_jobs"], capture_output=True)
                    if result.stdout.strip() == 'ml_http_503':
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError('worker did not preserve unavailable-model job')
                status, body = get(f"http://127.0.0.1:{api_port}/v1/predictions/{windows[0]['event_id']}", secret)
                if status != 200 or body['predictions'] != []:
                    raise RuntimeError('unavailable model produced a prediction')
                print('Native API + sensor + worker + actual Python ML: committed ingestion, 503 retained for retry, no false prediction.', flush=True)
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read()[-12000:])
                raise
            finally:
                for child in reversed(children):
                    if child.poll() is None:
                        child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)


if __name__ == '__main__':
    main()
