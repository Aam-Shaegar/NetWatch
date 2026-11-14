# NetWatch

Go-сборщик сетевого трафика + Python/PyTorch ML + web-интерфейс.
Текущий статус: **сенсор, доставка, PostgreSQL API и worker реализованы; обучение детектора впереди**.

## Начать работу

```sh
make bootstrap
make test
make build
make compose-check
```

Нужны Go 1.25+, Python 3.14, Node 22.12+ и Docker Compose.
Подробности: [рабочее окружение](docs/runbooks/development.md).

- [Стратегия и получение данных](docs/runbooks/data.md)
- [Контракты признаков](contracts/features.md)

`make api` запускает приёмник после настройки БД, токенов и `make migrate`
([инструкция](docs/runbooks/server.md)); `make worker` запускает обработку заданий.
`make ml` и `make web` запускают ML-сервис и каркас интерфейса. ML readiness остаётся
503 до появления проверенной модели; API readiness проверяет собственную БД.
`make lab-smoke` записывает настоящий HTTP-обмен в изолированной Docker-сети;
это smoke test, а не обучающая выборка.

Go: cmd/, internal/. ML: ml/. UI: web/. Контракты: contracts/. Стенд: deploy/lab/.
Старые netwatch/, examples/ и tests/test_core.py сохранены как legacy-прототип 0.1.
Для моделей используем собственные нормальные запуски и затем публичные PCAP;
готовые CICFlowMeter CSV не подменяют наши признаки. Датасеты не входят в Git.

Если uv отсутствует, bootstrap установит его только в .tools/ внутри проекта.

Реальный внешний образец IoT-23 зарегистрирован в data/manifests/iot23-somfy-01.json. Для длинных независимых нормальных записей использовать scripts/lab_smoke.py. Подробности в docs/runbooks/data.md.

## Чтение PCAP и PCAPNG на Go

```sh
mkdir -p outputs
go run ./cmd/netwatch-sensor replay --input tests/fixtures/pcap/syn-retry.pcap --output outputs/syn-retry.jsonl
```

В JSONL одна строка соответствует одной записи захвата. Для этого примера ожидаются две строки TCP по 40 IP-байт с одинаковыми адресами, портами и SYN-флагом. Команда печатает число обработанных записей и причины исключения в stderr. Выбирайте новое имя выходного файла: существующий файл сохраняется, а при ошибке незавершённый результат не публикуется.

Без --host/--service режим replay извлекает пакетные метаданные. Ограничения форматов описаны в [capture](internal/capture/README.md).

## Окна статистики

Добавьте к replay параметр --host или --service и идентификатор наблюдения --epoch:

```sh
go run ./cmd/netwatch-sensor replay --input tests/fixtures/pcap/syn-retry.pcap --output outputs/windows.jsonl --host 192.0.2.10 --epoch fixture --coverage-start 1700000000000000000 --coverage-end 1700000005000000000
```

Для сервиса используйте --service 198.51.100.20:443 --protocol TCP.
Границы --coverage-start/--coverage-end задаются в наносекундах и означают явно
подтверждённый непрерывный интервал наблюдения. При их отсутствии coverage=partial.
На эталоне двух SYN получается одно окно, 80 исходящих IP-байт и одна попытка TCP.
--lateness задаёт допустимое опоздание (по умолчанию 1s), --max-pending ограничивает
буфер пакетов, --max-unique ограничивает точные множества (по умолчанию по 100000).
Каждый независимый запуск или перезапуск должен получать новый --epoch.
Правила статистик и качества описаны в [window](internal/window/README.md).

## Linux live capture

`make live-smoke` builds the sensor and verifies real isolated Docker traffic against offline replay. See [the live runbook](docs/runbooks/live.md) for interface selection, BPF, capabilities, quality counters and limitations.

## Durable window delivery

Live capture can persist windows with `--spool` and send them with `--endpoint`. Offline imports use `enqueue`, accumulated queues use `send`, and `spool-status` reports pending data and loss. See [delivery guarantees and commands](docs/runbooks/delivery.md). The PostgreSQL receiver and leased inference worker are available; see [server setup](docs/runbooks/server.md).

## PostgreSQL ingestion and worker

`make server-smoke` verifies atomic ingestion, duplicate delivery, lease recovery, worker crashes and ML failures on an isolated real PostgreSQL. It also starts the actual API, sensor, worker and Python ML service; an unavailable model remains pending and never produces a normal prediction. See [server setup and guarantees](docs/runbooks/server.md).

Для сбора размеченных данных используйте `make collect`, затем `make dataset` с каталогами входа и результата. Профили, разметка, состав Parquet и команды приведены в [руководстве по данным](docs/runbooks/data.md).
