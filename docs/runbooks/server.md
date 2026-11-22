# PostgreSQL ingestion and inference worker

## Пилот на одном сервере Linux

Для установки на одну машину начните с [руководства для Linux](linux.md#analyzer). В нём описаны первый запуск, регистрация [локального](linux.md#local-sensor) и [удалённого](linux.md#remote-sensor) сенсора, диагностика и остановка. Ниже приведены параметры для ручного развёртывания и подробности работы API и очереди.

## Серверный запуск

Скопируйте [шаблон](../../deploy/work.env.example) в `.env.work` и задайте права `0600`. Укажите TLS-сертификат, ключ, данные PostgreSQL, операторские токены и комплект модели. `NETWATCH_DATABASE_URL` использует хост `db` внутри Compose и имя базы из `NETWATCH_DB_NAME`. При отдельной роли мигратора укажите `NETWATCH_MIGRATION_DATABASE_URL`. Сертификаты и модель монтируются для чтения контейнерным пользователем 65532.

Шаблон задаёт `COMPOSE_PROJECT_NAME=netwatch-v1`. Это имя выделяет отдельный том `netwatch-v1_pgdata`. Если локальный эксперимент уже применял другую миграцию 007, запустите v1 с отдельным именем проекта и томом. Проверка контрольной суммы остановит запуск на несовместимой схеме. Для параллельных стеков задайте разные `NETWATCH_API_PORT` и `NETWATCH_GRPC_PORT`.

Шаблон уже настроен для поставляемого временного детектора. Для самостоятельного однооконного комплекта очистите `NETWATCH_V1_TEMPORAL_BUNDLE` и задайте `NETWATCH_MODEL_DIR` с полным каталогом утверждённого комплекта, `NETWATCH_V1_MODEL_BUNDLE` с путём внутри контейнера, например `/model/bundle.json`, `NETWATCH_V1_MODEL_SHA256` с хешем этого файла и `NETWATCH_MODEL_ID` с его идентификатором. Для прежнего профиля используйте переменные `NETWATCH_LEGACY_MODEL_BUNDLE`, `NETWATCH_MODEL_SHA256` и `NETWATCH_SERVICE_MODEL_ENTITIES`. Необязательная `NETWATCH_DISABLED_RULES` перечисляет отключённые правила через запятую.

```sh
make work WORK_ENV=.env.work
make work-status WORK_ENV=.env.work
make work-logs WORK_ENV=.env.work
make work-stop WORK_ENV=.env.work
```

HTTPS для оператора по умолчанию доступен на `127.0.0.1:8443`, gRPC для сенсоров — на `127.0.0.1:8444`. Для удалённых сенсоров задайте `NETWATCH_GRPC_HOST` на доступном интерфейсе, откройте соответствующий порт только для нужной сети и используйте имя из TLS-сертификата. `NETWATCH_API_HOST` управляет операторским HTTPS отдельно. PostgreSQL и ML размещены во внутренней сети Compose.

При запуске PostgreSQL проходит проверку готовности, затем сервис `migrate` применяет миграции, а Compose ждёт готовности API, worker и ML. Воркер обрабатывает совпадения с правилами при временной недоступности ML. Задания, требующие инференса, остаются в очереди до восстановления. Операторский `GET /v1/pipeline/status` показывает глубину очередей, повторы и разрывы проекции.

Для прежнего Linux-сенсора с доставкой HTTPS/JSON включите профиль `sensor` через `COMPOSE_PROFILES` и задайте
интерфейс, фильтр, идентификатор и HTTPS endpoint. Если этот endpoint
использует частный УЦ, задайте `NETWATCH_SENSOR_CA_PEM` с публичным
сертификатом УЦ. Для Compose `.env` значение можно записать в одинарных
кавычках на нескольких строках. Имя в HTTPS endpoint должно присутствовать
в сертификате сервера. `NETWATCH_CAPTURE_BUFFER_MIB` задаёт размер буфера
захвата на сенсор в пределах от 1 до 64 МиБ. По умолчанию используется
16 МиБ. `NETWATCH_CAPTURE_LATENESS` задаёт, сколько Go ждёт переупорядоченные
пакеты перед закрытием окна. Значение по умолчанию `1s` входит в задержку
от конца окна до прогноза. Для конкретного интерфейса проверяйте другую
величину вместе с долей опоздавших пакетов и долей пригодных окон.
Этот профиль требует
отдельной приёмки на фактической точке захвата. Профиль `probe` запускает
одноразовую проверку доступности и публикует замеры в stdout. Импортёр может
доставить минутную сводку в устойчивую очередь через
`security_import --journal URL --queue telemetry ...`. Синхронный маршрут
остаётся доступен для существующих клиентов.

Для модели v1 подготовьте данные через `make v1-data`, обучите кандидатов офлайн через `make v1-train` и запустите `make test-find`, `make test-classify` или `make test-pipeline`. Передайте `MODEL=random_forest`, чтобы выбрать один вариант. `V1_DATA`, `V1_MODELS` и `V1_REPORT_DIR` задают пути к выборке, комплектам моделей и машиночитаемым отчётам. Прежний лабораторный профиль использует контейнерную команду `make train DATASET=... OUTPUT=...` и `make test-e2e`.

## Диагностика из терминала

Соберите операторский клиент через `make cli`. По умолчанию бинарник появится
в `bin/netwatch`. Для установки можно задать `CLI_OUTPUT` с абсолютным путём.
Передайте операторский токен отдельным файлом с правами `0600`. Для сертификата
частного УЦ укажите доверенный PEM-файл. CLI проверяет TLS и имя узла.

```sh
export NETWATCH_URL=https://127.0.0.1:8443
export NETWATCH_CA_FILE=/etc/netwatch/ca.pem
export NETWATCH_OPERATOR_TOKEN_FILE=/etc/netwatch/operator.token
bin/netwatch
bin/netwatch status --json
bin/netwatch doctor --json --max-age 30s
bin/netwatch incidents --since 1h
make work-status WORK_ENV=/etc/netwatch/work.env
```

В меню `netwatch` доступны статистика инцидентов с разбивкой по типам и источникам, список сенсоров и управление регистрацией. Меню тестирования запускает те же команды `make` в текущем каталоге. С другой рабочей директории задайте `NETWATCH_PROJECT_DIR` абсолютным путём к исходникам. Для выбора отдельной модели установите `MODEL`, а пункт «Сравнение моделей» запускает обе оценки для всех кандидатов.

`status` показывает модель, политику, возраст и качество последнего окна,
последнее решение и задержку его доставки и обработки, очередь инференса и
журнала инцидентов. Возраст окна считается от времени захвата. Возраст записи
считается от её получения API, поэтому задержанная доставка видна отдельно.
Потери относятся к показанному окну. Счётчики устройства захвата остаются в
структурированных логах сенсора. В установке с несколькими сенсорами CLI
показывает общий снимок и последнее полученное окно. Команда
`incidents --json` поддерживает фильтры `--entity`, `--model` и курсор `--before`.

`doctor` возвращает код `0`, когда срез пригоден для живого анализа, `2` при
неполадке сервиса или потока, `1` при неверных параметрах или локальной ошибке.
На только что запущенном стеке дождитесь первого полного окна и его прогноза.
`make work-status` дополняет этот вывод состояниями контейнеров.

В изолированной проверке `make test-e2e E2E_ARTIFACT=... E2E_POLICY=v2`
проигрываются остановка ML, перезапуски Go API, воркера и PostgreSQL,
обработка очереди после сбоя, доставка из spool сенсора по HTTPS и
восстановление дампа в отдельную БД.

## Подключение сенсора v1

Соберите сенсор на машине захвата из исходников с Go, CGO и libpcap. Установите бинарник в каталог из `PATH`.

```sh
mkdir -p bin
CGO_ENABLED=1 go build -trimpath -o bin/netwatch-sensor ./cmd/netwatch-sensor
```

В операторском меню выберите **Сенсоры → Добавить сенсор** и получите одноразовый код. На машине захвата укажите доверенный УЦ, если сервер использует частный сертификат. Вставьте код в интерактивное приглашение. Файл идентичности содержит постоянный секрет сенсора. Храните его отдельно от Git и выдавайте доступ только пользователю сенсора.

```sh
netwatch-sensor enroll --endpoint grpcs://netwatch.example:8444 \
  --ca-file /etc/netwatch/ca.pem --identity /var/lib/netwatch/sensor.json
netwatch-sensor live --interface eth0 --host 192.0.2.10 --filter 'host 192.0.2.10' \
  --spool /var/lib/netwatch/spool --endpoint grpcs://netwatch.example:8444 \
  --ca-file /etc/netwatch/ca.pem --identity /var/lib/netwatch/sensor.json
```

Укажите интерфейс и адрес фактического защищаемого узла. Дайте процессу права на чтение только нужного сетевого интерфейса и запись в свой каталог состояния. Из меню оператора можно приостановить приём наблюдений, возобновить его и отозвать доступ. На самом сенсоре доступны команды `pause`, `resume` и `remove` с параметром `--identity`. Перед удалением идентичности отзовите доступ в меню оператора. Для сохранения неподтверждённых наблюдений между перезапусками используйте тот же каталог `--spool`.

## Резервное копирование и восстановление

База хранится в томе `pgdata`. Обычная остановка и пересоздание контейнеров сохраняют том. Для восстановления после потери тома создавайте отдельные архивы PostgreSQL. Команда `backup` сохраняет согласованный снимок `pg_dump` в файл с правами `0600` и публикует файл только после успешного завершения. Задайте расписание резервирования по допустимому окну потерь и храните архивы в отдельном от машины PostgreSQL хранилище.

```sh
python3 scripts/stack.py work backup --env /etc/netwatch/work.env \
  --archive /var/backups/netwatch/netwatch-2026-11-21.dump
python3 scripts/stack.py work restore --env /etc/netwatch/work.env \
  --archive /var/backups/netwatch/netwatch-2026-11-21.dump \
  --database netwatch_restore
```

Восстановление проверяет архив, создаёт новую базу и загружает данные в одной транзакции. Для проверки существующей установки выберите новое имя базы, сравните число сенсоров и инцидентов, примените миграции к восстановленному экземпляру и проверьте готовность API. Для переключения задайте имя восстановленной базы в `NETWATCH_DB_NAME`, `NETWATCH_DATABASE_URL` и используемой отдельно `NETWATCH_MIGRATION_DATABASE_URL`, затем выполните `make work`. Последующие копии используют обновлённое имя базы. При отдельных ролях перед переключением восстановите права доступа из конфигурации PostgreSQL. Сохраните файлы TLS, настройки и утверждённые модели в штатном хранилище конфигурации.

## Local startup

Run `make bootstrap` once, then `make db-up`. Compose exposes development
PostgreSQL only on 127.0.0.1:54329. Load the locally generated credentials and set
the model ID from the trained artifact. For a queue-only experiment in a disposable database, use `pending-model`.

```sh
set -a
. ./.env
set +a
export NETWATCH_DATABASE_URL="$(python3 -c 'import os,urllib.parse; print("postgres://netwatch:"+urllib.parse.quote(os.environ["NETWATCH_DB_PASSWORD"],safe="")+"@127.0.0.1:54329/netwatch?sslmode=disable")')"
export NETWATCH_SENSOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export NETWATCH_SENSOR_TOKENS="$(python3 -c 'import os,json; print(json.dumps({"live":os.environ["NETWATCH_SENSOR_TOKEN"]}))')"
export NETWATCH_MODEL_ID="${NETWATCH_MODEL_ID:?Set the model ID from report.json first}"
export NETWATCH_POLICY_VERSION=v1
make migrate
make api
```

In another shell with the same database environment, run `make ml` and
`make worker` in separate terminals. The API defaults to 127.0.0.1:8080 and the
worker to http://127.0.0.1:8000/v1/predict. Without a configured model bundle and its pinned checksum, readiness and inference return 503. Jobs therefore remain
pending with `last_error=ml_http_503`; no normal prediction is invented. Use an
isolated development database for `pending-model` experiments. Job model/policy
identities are immutable snapshots; deployment of another model does not rewrite
existing jobs. See [detector setup](detector.md) to configure a trained model for new jobs.

A live sensor uses `--sensor live --spool data/spool/live --endpoint
http://127.0.0.1:8080/v1/windows` plus its capture/entity/output flags. Its
`NETWATCH_SENSOR_TOKEN` must match the `live` entry in the API token map. An offline
sender needs a token for the sensor_id already embedded in its windows (e.g.
`offline`); one batch cannot cross credential scopes. Never commit tokens or DSNs.
The token map is read at startup; rotate tokens by coordinated process restart.

`make server-smoke` starts an isolated PostgreSQL container on a random loopback
port and runs the real-database suite. It also builds and starts the API, sensor,
worker and actual Python service, checks committed ingestion and correct handling
of the missing model, then removes its processes/container/temporary files. It
never modifies the development database. Successful inference tests use a
controlled HTTP model fixture; they test pipeline correctness, not detection quality.
Without NETWATCH_TEST_DATABASE_URL, Go skips database-dependent tests. CI runs
server-smoke explicitly, so those checks are mandatory there.

## Migration and storage guarantees

`make migrate` executes `netwatch-api --migrate-only`. A transaction-scoped advisory
lock serializes migration runners. Applied SQL SHA-256 is stored in
schema_migrations; modifying an already applied migration fails. API and worker
startup require the expected schema. Neither silently creates application tables.

Migration 000001 creates:

- feature_windows: immutable JSONB window, global event_id primary key, sensor and
  event-time columns, received_at server time, sensor/time index;
- ingestion_batches: sensor-scoped batch ID, ordered event IDs and queue-loss
  snapshot; reuse with different content is a conflict;
- inference_jobs: unique (event_id, model_id, policy_version), state, attempts,
  availability time, lease token/expiry and last error;
- predictions: the same unique identity, model response and processed_at, with
  a foreign key to its job.

POST /v1/windows validates the entire bounded request before opening a transaction.
It writes the batch receipt, new windows and their jobs together. It sets
synchronous_commit=on for ingestion and prediction completion. PostgreSQL fsync
and storage durability must remain enabled; process-kill tests do not emulate
physical power loss. Only successful commit allows HTTP 200 ACK. Ambiguous
connection failures return no usable ACK and the sender can safely retry.

Equal event IDs with equal JSONB content are successful duplicates. Changed content
or a conflicting batch identity returns 409 and rolls back the entire batch.
Existing windows do not acquire new jobs when an API is restarted with a different
model setting. Window insert order is sorted by ID to avoid reversed-batch lock
ordering. Event timestamps remain decimal nanosecond strings in JSON and bigint
in PostgreSQL; original numeric values are preserved when normalizing JSON strings.

A matching down migration exists and is tested only in disposable schemas. A
rollback drops application data: back up first, stop writers, execute the down SQL
and delete its schema_migrations row in the same transaction. Production migration
credentials should own DDL; runtime roles only need SELECT/INSERT/UPDATE on the
application tables, DELETE on incident_queue, access to the identity sequences and SELECT on schema_migrations. See [incident review](incidents.md) for the operator role and migration 000002. Development Compose uses its
single local role. For backup and restore commands, see the [database recovery procedure](#резервное-копирование-и-восстановление).

## API behavior and bounds

NETWATCH_SENSOR_TOKENS is a JSON object mapping sensor IDs to distinct tokens of
at least 32 bytes. All window IDs in a request must belong to the authenticated
sensor. Bodies are bounded at 2 MiB/100 windows; headers at 64 KiB. JSON Content-Type
and matching Idempotency-Key/batch_id are required. Invalid windows return atomic
422 with their zero-based index. Duplicate IDs in one batch, malformed envelopes,
unsupported PostgreSQL NUL strings and future windows beyond five minutes are
rejected before persistence (indexed window errors use 422). Other sensor scope is
403; unknown credentials are 401. Storage errors return 503 without SQL details.

GET /v1/windows/{event_id} reads only the authenticated sensor's window.
GET /v1/predictions/{event_id} returns at most 100 result envelopes, each with
prediction, policy_version and processed_at; pending/absent/out-of-scope results
produce an empty array. These sensor-scoped JSON routes are not a browser login
or a complete dashboard API. `/health/live` reports process liveness;
`/health/ready` checks ingestion database/schema readiness, independently of ML.

Default listening is loopback. A non-loopback listener requires NETWATCH_TLS_CERT
and NETWATCH_TLS_KEY, or the explicit NETWATCH_ALLOW_INSECURE_HTTP=true exception
for a trusted isolated lab. Use verified TLS for remote PostgreSQL connections
(`sslmode=verify-full` with the appropriate CA) and HTTPS for remote ML.
Never expose the development PostgreSQL port or plain HTTP lab configuration as a
production deployment. Request bodies and credentials are not logged.

## Worker leases, retries and fairness

Claims use PostgreSQL time and FOR UPDATE SKIP LOCKED. A claim increments attempts
and installs a fresh random lease token; inference runs after the claim transaction,
without holding a database row lock during HTTP. Defaults:

- NETWATCH_LEASE=30s;
- NETWATCH_ML_TIMEOUT=10s (lease must be at least twice this timeout);
- NETWATCH_WORKER_POLL=250ms;
- NETWATCH_ML_ENDPOINT=http://127.0.0.1:8000/v1/predict.

One worker processes one window at a time. Four claims favor the newest event-time
windows; every fifth favors the oldest eligible job. This gives fresh observations
priority while reserving capacity for backlog. Retry availability timestamps keep
an unavailable old job from blocking every new job. Multiple workers can run with
independent claim counters. Empty queues and storage failures use bounded polling.

The request is an inference-request envelope with target model/policy and a
one-window batch. The response must satisfy inference-response and prediction
schemas and match event/model/feature-set identities. Responses are bounded to
64 KiB; redirects are not followed. HTTP errors, timeouts, invalid identities or
scores, and model status=error reschedule the job with bounded exponential jitter
(up to 60 s). Non-scored valid statuses such as warming_up or insufficient_data
can be stored, but they have null scores. No model availability is inferred from
HTTP liveness.

On completion the worker locks and verifies the current, unexpired lease token.
It inserts the unique prediction and marks the job done in one transaction. An
expired/reassigned worker cannot overwrite or finish the new owner's job. A crash
after inference but before commit may call ML again after lease expiry; it cannot
create a second prediction for the same identity. SIGTERM cancels HTTP and shuts
down; an interrupted lease is left to expire. A database error after inference
also leaves recovery to the lease. Jobs retry rather than silently disappearing;
operators can inspect pending attempts/last_error in PostgreSQL.

### Permanent inference rejection

A structured 409 incompatible_model_or_policy or 422 invalid_inference_request
from the ML service completes the job with status error, a reason and null
scores. The projector can advance. Connection errors, 503 and invalid responses
remain retryable. The journal reports terminal errors and the prediction API
exposes the reason for the individual event. After validating a corrected model,
an operator can schedule the affected windows under its new identity. Set the
psql variable new_model to the deployed model ID before running this statement.

    INSERT INTO inference_jobs(event_id,model_id,policy_version)
    SELECT event_id, :'new_model', policy_version FROM predictions
    WHERE payload->>'reason' IN ('incompatible_model_or_policy','invalid_inference_request')
      AND model_id <> :'new_model'
    ON CONFLICT DO NOTHING;

Each new model has its own event-time incident stream and keeps the original error for audit.
