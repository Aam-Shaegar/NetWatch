# NetWatch

Go-сборщик сетевого трафика + Python/PyTorch ML + web-интерфейс.
Текущий статус: **подготовленный монорепозиторий, не готовый детектор**.

## Начать работу

```sh
make bootstrap
make test
make build
make compose-check
```

Нужны Go 1.25+, Python 3.14, Node 22.12+ и Docker Compose.
Подробности: [рабочее окружение](docs/runbooks/development.md).

- [Главная инструкция](docs/IMPLEMENTATION_GUIDE.md)
- [Статусы этапов](PLAN.md)
- [Проверки текущей подготовки](docs/status.md)
- [Стратегия и получение данных](docs/runbooks/data.md)
- [Контракты признаков](contracts/features.md)

`make api`, `make ml`, `make web` запускают каркасы сервисов. Readiness намеренно 503:
модель и конвейер пока не реализованы. `make lab-smoke` записывает настоящий HTTP-обмен
в изолированной Docker-сети; это smoke test, а не обучающая выборка.

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

Режим replay извлекает пакетные метаданные. Расчёт временных окон и объединение повторного SYN в одну попытку соединения — следующий этап. Ограничения форматов описаны в [capture](internal/capture/README.md).
