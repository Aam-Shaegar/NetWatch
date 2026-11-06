# NetWatch — руководство по проектированию и реализации

Версия 2.0 · 6 ноября 2026 · статус: согласованное направление и предлагаемый план, реализация новой архитектуры ещё не начата.

## 1. Назначение и правила работы с документом

Создать систему пассивного анализа сетевого трафика: Go-сенсор собирает метаданные, рассчитывает признаки и передаёт их ML-сервису; Python/PyTorch обнаруживает аномалии; сервер сохраняет результаты и показывает инциденты. После готовности основной системы добавить классификацию известных типов аномалий с проверенными вероятностными оценками.

Официальная тема: «Разработка системы анализа сетевого трафика и обнаружения аномального поведения».

Этот файл — главный технический источник для пользователя и агента. PLAN.md — короткий индекс и текущие статусы. Решения, изменяющие контракты или измерения, фиксировать отдельным ADR в docs/adr. Не отмечать этап выполненным без артефактов и проверки его критерия готовности. Все команды далее — целевой интерфейс, который предстоит реализовать, а не утверждение о наличии команд сейчас.


### Реальное состояние на начало плана

Исходная версия включала Python-прототип CSV → окна → пороги → JSON.

### Что означает production-ready

Цель — поддерживаемый продукт с ограниченной и проверенной областью применения. Наличие Docker, нейросети и красивого интерфейса недостаточно. Релиз готов только после испытаний на заявленной платформе, нагрузке, отказах, восстановлении и безопасности. До этого используем формулировки «прототип» и «кандидат в релиз».

Первый профиль эксплуатации: один Linux-сенсор и один наблюдаемый сегмент/сервис, CPU-инференс, пассивное наблюдение. На macOS — разработка, анализ PCAP и Docker Desktop-стенд внутри Linux VM. Нативный захват macOS — отдельный профиль с отдельными проверками. Не обещаем поддержку 10/100 GbE, всей корпоративной сети, расшифровку TLS, автоматическую блокировку или установление причины сбоя.

## 2. Версии и границы продукта

- M0: контракты, тестовые пакеты и воспроизводимый offline-анализ на Go.
- M1: живой сенсор, доставка, хранение, Isolation Forest, журнал и интерфейс. Первый полезный продукт.
- M2: GRU на PyTorch, воспроизводимые эксперименты, сравнение с простыми методами.
- M3: эксплуатационная готовность детектора на одном заявленном профиле.
- M4: классификация известных типов аномалий, калибровка и повторная приёмка.

Продукт сообщает: нормальное наблюдаемое поведение, подозрительное отклонение, недостаточно данных, деградация наблюдения. В дальнейшем — известный тип или отказ от классификации. Сбой сенсора и отсутствие пакетов не равны нормальной работе сети.

## 3. Архитектура и ответственность компонентов

Путь данных:

Сетевой интерфейс / PCAP → Go sensor → состояния потоков → временные признаки → локальная устойчивая очередь → Go API → PostgreSQL и задания → Python inference → оценки → Go incident engine → API → web UI.

Обучение идёт отдельно: сохранённые признаки + независимая разметка → проверка данных → train/validation/calibration/test → модель и отчёт → модель-кандидат → теневой режим → активация.

### Компоненты

1. sensor: отдельный Go-процесс с правами только на захват. gopacket/libpcap для первого backend. Интерфейсы источника позволяют позже добавить AF_PACKET/eBPF без изменения ML-контракта; сейчас их не реализовывать.
2. api: Go net/http, управление сенсорами, приём batch, запросы UI, incidents. Единственный владелец прикладной схемы БД.
3. worker: Go-процесс или режим API-процесса. Забирает задания с арендой из PostgreSQL, вызывает Python, сохраняет результат и обновляет incident state.
4. ml-service: Python + FastAPI + PyTorch + scikit-learn. Получает признаки/готовую историю, нормализует, считает score, возвращает результат. Не захватывает пакеты и не обучается на HTTP-запросе.
5. trainer: Python CLI, отдельно от serving. Формирует датасеты и model bundle. Не требует поднятого UI.
6. web: TypeScript + React, минимальный интерфейс мониторинга. В production собранные статические файлы отдаёт Go API. Никакой зависимости от CDN для работы.
7. PostgreSQL: конфигурация, агрегаты, задания, оценки, инциденты, аудит. Для первой версии не добавлять Kafka/Redis/Kubernetes.
8. lab: Docker Compose, целевой сервис, клиенты, сенсор, управляющий сценариями процесс. Продукт и стенд разделены конфигурациями.

Связь: HTTP/JSON batch с OpenAPI/JSON Schema. На локальном стенде приватная сеть; при выносе на разные хосты TLS и отдельная идентификация сенсора. Переход на gRPC — по результату профилирования, не заранее.

Модель не должна хранить единственную копию истории узла в памяти: worker собирает последовательность из сохранённых окон. Для малого профиля это проще и воспроизводимее. Кэш допустим позже, но рестарт не меняет семантику результата.

## 4. Структура репозитория

```text
cmd/netwatch-sensor/main.go
cmd/netwatch-api/main.go
cmd/netwatch-worker/main.go
internal/config/              # проверка конфигурации и effective config
internal/capture/             # live, pcap, pcapng; интерфейс Source
internal/decode/              # пакеты → ограниченные метаданные
internal/flow/                # ключи, направления, TCP state, timeouts
internal/window/              # event time, окна, качество покрытия
internal/features/            # единственная реализация online/offline признаков
internal/spool/               # bounded durable queue, recovery
internal/transport/           # batch, retries, auth
internal/api/                 # handlers, validation, middleware
internal/store/               # PostgreSQL, transaction boundaries
internal/jobs/                # lease, retry, deduplication
internal/incidents/           # hysteresis, merge, lifecycle
internal/telemetry/           # logs, metrics, health
contracts/                   # schemas, OpenAPI, golden fixtures
migrations/                  # последовательные SQL-миграции
ml/netwatch_ml/data/          # manifests, split, validation, sequences
ml/netwatch_ml/features/      # только preprocessing, не пересчёт пакетов
ml/netwatch_ml/models/        # threshold, EWMA, IF, GRU, classifier
ml/netwatch_ml/training/
ml/netwatch_ml/evaluation/
ml/netwatch_ml/serving/
ml/tests/
web/src/
deploy/compose.yaml
deploy/lab/compose.yaml
lab/scenarios/
lab/runner/
tests/fixtures/pcap/
tests/integration/
tests/e2e/
benchmarks/
configs/
docs/adr/
docs/runbooks/
docs/model-cards/
```

Старый пакет netwatch/ не удалять на первом шаге. Пометить legacy prototype и убрать из рекомендуемого запуска после подтверждения эквивалентности M0. Не создавать две конкурирующие реализации признаков в Python и Go.

## 5. Контракты и определения до написания модели

### 5.1 PacketMeta

Минимум: sensor_id, interface_id, timestamp_ns, src/dst IP, IP version, protocol, src/dst port при наличии, captured_length, wire_length при наличии, ip_length, TCP flags, TCP seq/ack при необходимости, decode_status. Payload не сохранять. Размеры разных уровней не смешивать; основной byte_count — длина IP-пакета.

Время в Go — int64 наносекунд UTC. В JSON timestamp_ns передавать десятичной строкой: JavaScript Number не хранит все int64 точно. В БД и Parquet — integer с указанными единицами; время интерфейса — ISO 8601. Отдельно wall clock и monotonic time для таймаутов исполнения. IP канонизировать.

Статусы: decoded, non_ip, unsupported_linktype, truncated, fragment, malformed. Для M0 исключаем фрагменты и недекодируемые записи из ML-признаков, но считаем их отдельно. Это ограничение модели, а не «чистка без последствий». PCAPNG может содержать несколько интерфейсов и разные разрешения времени — либо корректно поддерживаем, либо явно отказываем, не угадываем.

### 5.2 FlowState

Ключ двунаправленного TCP/UDP-потока: каноническая пара IP/port + protocol + sensor observation domain. Инициатор — по первому SYN без ACK, иначе unknown/first_seen, не по «меньшему номеру порта». Храним направление относительно выбранной entity.

Стартовые параметры, подлежащие испытанию: TCP idle timeout 60 s, UDP 30 s, active snapshot 5 s, лимит состояний 100 000. FIN, RST, повторный SYN и повторное использование 5-tuple покрыть тестами. Повтор SYN не считать новым успешным соединением. Состояния с неизвестным началом/концом маркировать censored. Не называть RST доказательством отказа приложения. Длительность завершённого потока появляется только после его завершения; данные из будущего не добавляются в ранние окна.

### 5.3 Entity и два направления анализа

- host: поведение конкретного наблюдаемого узла, входящие и исходящие признаки, разнообразие адресатов/портов. Нужно для необычного исходящего поведения и сканирования.
- destination_service: IP назначения + service port + transport, суммарный входящий поток всех наблюдаемых отправителей и ответы сервиса. Нужно для DDoS: активность каждого отдельного источника может быть небольшой.

Для established flow направление сервиса определяем конфигурацией наблюдаемого сервиса и состоянием потока. Не строить «сервис» из каждого клиентского ephemeral port. В MVP сервисы задаются явно; автоматическое discovery — позже. ICMP обрабатывать отдельно без выдуманных портов. NAT, асимметричный захват и неполная видимость отражаются в observation profile.

### 5.4 FeatureWindow v1

Ключ: schema_version, feature_set_version, sensor_id, capture_epoch, entity_type, entity_id, window_start, window_end. event_id — стабильный идентификатор этого ключа. Capture epoch меняется при запуске нового источника/сессии. Для PCAP replay используется manifest run_id.

Окно 5 s, полуоткрытое [start,end), по event time. Source поддерживает watermark: закрываем окно после допустимого опоздания (начальная настройка 1 s). EOF offline закрывает остаток как partial. Слишком поздние пакеты учитываются в late counter; опубликованное окно не переписывается молча. Для отдельных batch с нарушенным порядком worker ждёт историю до установленного deadline, затем ставит missing_context.

Признаки v1, точные формулы и единицы записать в contracts/features.md:

- inbound/outbound packet_count и ip_bytes;
- pps/bps = count / полная длина окна, плюс observed_duration и coverage_status;
- unique peers, destination ports у host, unique sources у service;
- active flows, new TCP attempts, established attempts;
- SYN/RST fractions с явно определённым знаменателем;
- packet size mean/std, межпакетный интервал mean/std;
- completed flow duration mean, count completed и censoring fraction;
- доли TCP/UDP/ICMP, incoming/outgoing ratio с устойчивым знаменателем;
- для service — степень концентрации источников, число новых источников.

Начать с 15–25 доступных признаков на entity type; расширять только с тестами и новой версией. Host и service имеют разные модели/наборы признаков. Нулевой знаменатель: nullable + valid mask, не NaN/Infinity и не произвольная константа.

Качество отдельно: capture_drops_known/unknown, decode counts, state_evictions, queue_loss, late events, partial window, observed coverage. Не подавать учебные run_id, labels, IP, абсолютную дату, имя файла или scenario_id в модель. Показатели качества сначала использовать для abstention, а не позволять модели классифицировать сбой сбора как атаку.

Нулевые окна создаются только для наблюдаемых configured entities при подтверждённой работе capture heartbeat. Не создавать бесконечные пустые окна для когда-либо увиденных адресов. Правила TTL и warmup — часть feature contract.

### 5.5 Prediction и Incident

Prediction: event_id, model_id, preprocessing_version, score, threshold, status, observed_at, processed_at, top_deviating_features. status = normal / anomalous / warming_up / insufficient_data / degraded / error. Score не является вероятностью.

Incident: id, entity, first_observed, detected_at, last_observed, closed_at, contributing event_ids, severity, detector/model versions, причины, acknowledged_by. Отдельно сохраняем event time и delivery time.

Начальная политика: два превышения из трёх последовательных валидных окон открывают инцидент, три валидных нормальных закрывают; lower closing threshold для hysteresis. Пропуски не закрывают инцидент как «норму». При длительной потере наблюдения состояние unknown/stale. Группировка по entity, detector и конфигурации политики, а не объединение всей сети. Эти настройки калибруются на validation; для всех сравниваемых методов политика одинакова.

Top deviations — признаки с наибольшими отклонениями/ошибками прогноза. Это диагностическая подсказка, не причинное объяснение и не доказательство атаки.

## 6. Доставка, хранение и отказоустойчивость

1. После закрытия окна sensor записывает событие в append-only spool с checksum и sequence. Размер по умолчанию ограничен, например 256 MiB; файл сегментируется.
2. Sender читает batch: до 100 окон или каждые 250 ms. HTTP timeout, exponential backoff с jitter, прекращение при shutdown через context.
3. API валидирует всю схему и в одной транзакции вставляет окна и jobs. ACK только после commit. UNIQUE(event_id) делает повторы безопасными.
4. В MVP batch атомарен: при невалидном событии возвращается error index, сенсор помещает его в bounded quarantine, сообщает health error и не зацикливает весь поток. Остальные события повторяются с теми же ID.
5. Worker арендует job на ограниченный срок. После timeout job доступен повторно. Результат UNIQUE(event_id, model_id, policy_version); повтор не создаёт инцидент второй раз. Очередь и commit incident обновляются транзакционно.
6. Если spool заполнен: явно настроенная drop-newest policy, счётчик и журнал потерянного диапазона; heartbeat сообщает degraded. Не блокировать capture бесконечно и не обещать отсутствие потерь.
7. Очередь live имеет приоритет над историческим replay. Старые события анализируются как delayed; UI различает текущие и исторические сигналы.
8. Рестарт восстанавливает spool. Незакрытое окно и незаписанный хвост могут быть потеряны — явно фиксируем границу гарантий, recovery и epoch.

Таблицы: sensors, feature_windows, inference_jobs, predictions, incidents, incident_events, models, configurations, audit_log. Индексы sensor/entity/time, status/available_at для jobs; cursor pagination для UI. Миграции версионировать и тестировать на предыдущей версии.

Retention задавать до больших запусков: окна, например, 7 дней; incidents 90 дней; PCAP по умолчанию не сохранять. Это стартовая политика, а не вместимость любого сервера. Рассчитать объём: entities × 86400/5 × размер строки × дни + индексы. Обучающие наборы экспортировать отдельными Parquet-артефактами с manifest, не удерживать бесконечную историю в OLTP-БД.

Бэкап БД, тест восстановления и проверка consistency модели/предобработки — обязательны до M3. Не хранить метки событий только в UI.

## 7. Модели и порядок их реализации

### 7.1 Простые методы

Сначала фиксированные пороги → EWMA → Isolation Forest. Это проверка конвейера и обязательная база сравнения. IF обучать на проверенных нормальных данных; score ориентировать так, чтобы больше значило аномальнее. Threshold подобрать отдельно. Не использовать contamination как доказательство реальной доли атак.

EWMA baseline обновляется только по прошлым данным. Для первого честного сравнения зафиксировать режим адаптации; не допускать обучения на тестовых метках. Автоматическую адаптацию в production включать только отдельным ADR после проверки poisoning/drift.

### 7.2 GRU-прогноз на PyTorch

Предложение для первой модели: история 12 окон × F признаков, один GRU слой hidden_size=64, linear head → F признаков следующего окна. CPU — основной режим. Отдельные bundle для host и destination_service, веса общие между entities одной роли; не обучать отдельную сеть на каждый IP без необходимости.

Преобразования: log1p для подходящих неотрицательных count/rate, нормализация по train, valid masks, versioned feature order. Пропуски и partial windows не приравнивать к нулю. Обучение на normal train, Huber loss по валидным координатам. Нормализатор никогда не fit на validation/test.

Runtime: хранить историю прошлых окон → предсказать x_t → получить фактический x_t → вычислить ошибку → выдать score. Нельзя включить x_t во вход для его же прогноза. После 12 валидных непрерывных окон заканчивается warmup. На gap — reset/warmup или отдельный обученный mask-aware режим; MVP выбирает reset.

Score: средняя стандартизованная абсолютная ошибка валидных признаков; масштаб residual оценить на отдельной validation части, с минимальным epsilon. Глобальный score и top deviations вернуть вместе. Не подбирать состав score на test.

Threshold и incident policy выбираются по false-alert budget на валидационных нормальных запусках и recall на отдельных размеченных валидационных событиях. High quantile сам по себе не гарантирует нужного количества алертов в час после объединения.

Optimizer, learning rate, epochs, early stopping, seeds фиксируются конфигурацией. Стартовый эксперимент AdamW, lr=1e-3, batch=128, максимум 50 epochs, early stopping patience=5; подтвердить на фактических данных. Не обещаем преимущество GRU над IF: выбираем модель по измерениям при сопоставимом бюджете ложных тревог.

### 7.3 Контекст нагрузки

После базовой GRU добавить вариант с внешним спросом: число инициированных клиентом запросов, расписание штатного фонового обмена, известная роль сервиса. Источник — генератор или отдельно наблюдаемый вход сервиса, не число внутренних ретраев, уже вызванных сбоем.

Context должен быть доступен при реальном инференсе в момент прогноза. Поздние application metrics нельзя задним числом использовать как известное будущее. Если внешний спрос недоступен, используется отдельная network-only модель. Сравнение: одинаковые splits, seeds, hidden size, policy; ablation без контекста и с ним.

### 7.4 Model bundle

Manifest содержит model_id, SHA256, framework/dependency versions, feature_set_version, ordered features, preprocessing, training manifest hash, split IDs, seed, threshold, incident policy, intended observation profile и evaluation report. Сохранить state_dict, а не произвольный сериализованный Python executable object. Загрузка только доверенных артефактов, размер ограничен, hash проверяется. API не принимает произвольный путь к модели из пользовательского запроса.

Перед serving: validate schema → load → golden prediction → warmup → readiness. При несовместимости модель не активируется. Model registry сначала каталог артефактов + таблица models; MLflow и ONNX только при доказанной необходимости. Активировать атомарно, сохранять предыдущую версию для rollback; по умолчанию не обновлять модель во время открытого инцидента без сохранения provenance.

## 8. Данные и честная оценка

### Источники

1. Наш Docker-стенд — главный источник end-to-end проверки и контролируемой normal baseline.
2. CIC-IDS2017 — кандидат для нескольких типов поведения; содержит PCAP и размеченные flow CSV [S1]. У исходного набора известны проблемы построения потоков и разметки; учитывать опубликованные исправления [S3].
3. CIC-DDoS2019 — кандидат для DDoS-сценариев, PCAP и размеченных потоков [S2]. Это стендовый набор, а не доказательство эффективности в современной рабочей сети.

Не скачивать весь набор до data audit. Сначала небольшой репрезентативный фрагмент, условия использования/цитирования, доступность PCAP, объём диска, версия, checksums и соответствие целевой точке наблюдения. Не считать наличие сайта гарантией рабочего download.

### Совместимость признаков

Готовые CICFlowMeter CSV нельзя просто подать модели, которая в production получает другие Go-признаки. Основной путь: исходный PCAP → тот же Go extractor → наши окна. Flow labels используются только для отдельного label join. IP и timestamp разрешены для join, но не для обучения как признаки.

Оконные метки связывать по времени, направлению, entity и потокам. Одновременные normal/attack, пересечения классов, неуверенные метки сохранять как mixed/uncertain, а не автоматически делать «все окна в этот день = атака». Для первого классификатора использовать надёжно размеченные окна; отдельно оценить переходные/смешанные. Правила агрегации labels фиксировать до обучения.

Полные характеристики завершённого потока не доступны в начале live-соединения. Любой признак, требующий будущих пакетов, исключить из online-фич или перевести в snapshot с каузальной семантикой.

### Разделение

Дедупликация → группировка по capture/day/run/scenario instance → train / validation / calibration / locked test. Никакого случайного смешивания соседних окон и того же потока между частями. GRU sequences не переходят границы split; в начале каждой части заново warmup.

Train: fit preprocessing и weights. Validation: архитектура, thresholds, policy. Calibration: вероятностная калибровка классификатора, отдельная от выбора модели. Test: однократная итоговая оценка. Если данных мало — grouped nested validation внутри development набора, но тест остаётся закрытым.

Внешний dataset и локальный стенд оценивать раздельно. Не делать train на CIC и обещать тот же процент на домашней сети. Держать отдельный unknown-family test, новые нормальные нагрузки, другую раскладку IP/портов и новый seed. Перестановка IP должна менять идентификаторы, но не вывод на эквивалентных признаках.

### Метрики

- По окнам: precision, recall, F1, PR-AUC; ROC-AUC только дополнительно.
- По событиям: доля найденных, число пропусков, задержка от onset до первого подтверждённого сигнала.
- Ложные инциденты / час подтверждённого normal-наблюдения; также entity-hours при разном числе узлов.
- Пропуски наблюдения/coverage и доля времени, когда детектор abstained.
- Производительность: pps, drops, CPU/RSS, очередь, p50/p95/p99 inference и end-to-end latency.
- Не применять point adjustment. Отдельно показать задержки среди обнаруженных и долю пропусков.
- Повторы минимум на 5 независимых runs для каждого ключевого сценария; доверительные интервалы по runs, не по коррелированным окнам. 5 — старт для отладки, не универсальная достаточность статистики.

## 9. Docker-стенд и реалистичные испытания

### Топология A — минимальная и проверяемая

client-normal + client-extra-1 + client-extra-2 → target HTTP/TCP/UDP service.

Sensor использует network_mode: service:target: разделяет namespace target и видит трафик его интерфейса. Это поддерживаемый механизм Compose [S4]. Снимаем трафик target, а не предполагаем видимость всего bridge из произвольного контейнера.

Target подключён к lab_data (internal: true) и к lab_control; генераторы только к lab_data. API/ML/DB на lab_control, не на lab_data. Общий namespace sensor/target неизбежно включает оба интерфейса: сенсор выбирает capture interface/BPF по lab_data subnet, не по предположению, что eth0 всегда нужный. Target не маршрутизирует между сетями. Sensor egress идёт через lab_control; его служебный трафик исключён capture filter. В lab_control у генераторов доступа нет.

Web/API опубликован только на 127.0.0.1. У target и генераторов наружу порты не публикуются. Сначала собрать образы и зависимости, затем запускать изолированную сеть. У generator нет произвольного внешнего target: runner принимает service из allowlist, задаёт duration, rate, concurrent clients, hard timeout. Ресурсы CPU/memory/pids ограничены. Ни адреса интернета, ни сеть университета не входят в испытания.

NET_RAW выдаётся только сенсору по необходимости backend. NET_ADMIN — только отдельному fault-injection компоненту/namespace для netem, не API/ML. Не использовать privileged: true или монтирование Docker socket в рабочие сервисы. Lab runner может запускать Compose с хоста; это отдельный доверенный инструмент.

### Топология B — следующий уровень

На отдельной Linux VM два сегмента и маршрутизирующий gateway. Трафик client→target обязан проходить через gateway, сенсор захватывает одну согласованную сторону, чтобы не удваивать пакеты. Проверить путь traceroute/контрольными пакетами и counters. SPAN/TAP и несколько сенсоров — позднее расширение.

На Docker Desktop host networking имеет ограничения и не является эквивалентом доступа к физическому сетевому интерфейсу [S5]. Поэтому испытания реального сегмента проводить на Linux VM/host; на Mac демонстрируем container-to-container наблюдение и PCAP replay.

### Сценарии

| Сценарий | Что меняется | Что проверяем |
|---|---|---|
| Stable normal | равномерные HTTP/TCP/UDP запросы | базовые счётчики, отсутствие лишних сигналов |
| Normal ramp | плавное увеличение числа клиентов | устойчивость к штатной смене нагрузки |
| Flash crowd | легитимный короткий всплеск | ложные тревоги при росте спроса |
| Background transfer | ограниченная крупная передача | большой объём не равен атаке |
| Port spread | ограниченные подключения к портам собственного target | разнообразие портов и host-детектор |
| Connection retry | управляемые ошибки/таймауты target | повторные попытки и temporal pattern |
| Single-source overload | ограниченная нагрузка одного клиента | DoS-подобный сценарий, не DDoS |
| Multi-source overload | несколько независимых контейнеров на один target | service-агрегация, DDoS-подобный сценарий |
| Network degradation | delay/loss/bandwidth внутри lab | эксплуатационные аномалии отдельно от атак |
| Collector/service failure | остановка sensor/ML/DB, backlog | качество наблюдения и восстановление |

Пара контейнеров достаточна для проверки захвата и признаков. Для распределённого сценария нужны несколько источников. Даже такой стенд не воспроизводит интернет-масштаб DDoS и не доказывает злонамеренность: одинаковый всплеск бывает штатным. Записывать фактическую деградацию target отдельно: request latency, error rate, CPU, successful request rate. Если сервис не пострадал, не объявлять доказанный отказ в обслуживании.

### Порядок одного эксперимента

1. Сохранить experiment_id, config hash, git commit, image digests, seed, лимиты и сведения о хосте.
2. Поднять target, sensor и pipeline; дождаться readiness; проверить видимость нескольких контрольных пакетов.
3. Запустить нормальный прогрев, достаточный для flow state и 12 окон GRU.
4. Runner записывает requested и actual start/stop событий в отдельный ground_truth.jsonl. Генератор подтверждает реальные моменты и достигнутую нагрузку.
5. Выполнить сценарий с жёстким deadline; сохранить delivered/requested rates, не считать заданный rate достигнутым автоматически.
6. Сохранить признаки, predictions, incidents, capture stats и метрики target. PCAP сохранять только в lab на ограниченное время и объём.
7. Дождаться конца событий, late watermark и graceful flush. Сбой и неполное окончание сохраняются в manifest.
8. Повторить offline обработку того же PCAP тем же Go extractor и сравнить семантически эквивалентные окна; учесть startup/EOF boundaries и capture loss.
9. Evaluation CLI формирует JSON/CSV и графики; никаких ручных исправлений результатов ради красивой метрики.

### От лаборатории к эксплуатации

После лаборатории — shadow mode на собственном сервисе: система только наблюдает, оператор отмечает события. Сначала несколько суток, затем минимум неделя пилота с разными normal regimes. Пилот без разметки не измеряет recall атак, но выявляет стабильность, нагрузку и nuisance alerts. Ни одно действие блокировки не выполняется автоматически.

## 10. Интерфейс и API

Экраны: обзор состояния наблюдения; сущности host/service; временные графики и score; список инцидентов; карточка инцидента; импорт PCAP как offline job; модели и конфигурация; состояние сенсора.

Показывать источник данных, observation profile, model version, порог, период warmup, пропуски и задержку доставки. Нельзя рисовать зелёный «всё нормально», если модель недоступна. Режим replay явно отличается от live. Timestamp отображается в выбранной зоне, хранение — UTC.

API v1:

- POST /v1/windows: authenticated batch сенсора;
- POST /v1/heartbeats;
- GET /v1/sensors, /v1/entities, /v1/windows;
- GET /v1/incidents и /v1/incidents/{id};
- POST /v1/incidents/{id}/ack;
- POST /v1/imports: bounded file upload → isolated background processing job;
- GET /v1/imports/{id};
- GET /v1/models; POST /v1/models/{id}/activate для admin;
- /health/live, /health/ready, отдельный /metrics.

ML internal endpoint POST /v1/predict принимает batch с историей и версиями. Readiness проверяет загрузку модели. Ответ сохраняет сопоставление event_id даже при частичных ошибках.

Пагинация, ограничения диапазона графиков, максимальный размер upload, timeout, cancellation и typed errors обязательны. Untrusted PCAP обрабатывается отдельным worker с memory/time limit. UI не вставляет имена файлов и сетевые поля как HTML. Browser API и sensor ingestion имеют разные credentials и permissions.

## 11. Эксплуатационная готовность

### Наблюдаемость

Structured JSON logs: component, sensor_id, event_id, model_id, latency, error code; не печатать payload и secrets. Метрики: packets_received, capture_dropped, decode_failed, flows_active/evicted, windows_emitted, late_packets, spool_bytes, oldest_pending_age, jobs_retried, predictions_failed, abstention_rate, incidents_opened. IP/entity ID не использовать как бесконечно растущие Prometheus labels.

Liveness означает процесс жив; readiness — способен выполнять свою роль; degraded capture — отдельный сигнал. Наличие HTTP 200 не доказывает видимость трафика.

### Начальный профиль приёмки — гипотеза, не обещание

Зафиксировать конкретный Linux host (например 4 vCPU, 8 GiB) и фактическую версию окружения. Начальный benchmark: 10 000 packets/s, 1 000 активных потоков, 100 наблюдаемых entities, 5 s window. Размеры пакетов и их распределение фиксировать; packets/s не заменять битрейтом.

Предлагаемые engineering budgets: p95 обработки закрытого окна до сохранённой prediction ≤1 s без backlog; sensor RSS ≤512 MiB; capture drops <0,1% в выбранном тесте; 24 h soak без необъяснимого роста памяти. Это критерии первого профиля, корректируются до итогового теста через ADR, не после неудачи скрытым снижением требований.

Detection latency отдельно: включает накопление окна, watermark, warmup и policy. Для начальной policy ожидаемый бюджет подтверждения устойчивого события порядка 15 s после onset при прогретой модели; измерить, не выводить из скорости infer. Короткие события оценивать отдельно.

Quality gates: сначала согласовать измеримый false-alert budget на normal runs (стартовый ориентир ≤1 ложного инцидента/час для всего заявленного стенда), затем максимизировать recall при этом бюджете. 1/час может быть неприемлемо для реального оператора; для production pilot бюджет ужесточается по результатам. При нуле сигналов на коротком тесте не заявлять нулевую реальную частоту.

### Надёжность и безопасность

Проверить: kill -9 и recovery spool; ML timeout; DB unavailable; duplicate batch; disk full; invalid schema; corrupted artifact; model mismatch; рестарт в середине потока; timezone/clock jump; пересечение capture interfaces; backlog recovery; graceful shutdown. При невозможности расчёта — insufficient_data/degraded, а не normal.

Local UI по умолчанию loopback. Для remote: TLS, auth, роли viewer/operator/admin, session expiry, CSRF для cookie endpoints, защищённые sensor tokens, rate limits, audit конфигураций и model activation. Не писать свою криптографию. Secrets из environment/secret store, не Git.

Минимальные capture privileges; API/ML non-root; read-only image filesystem с отдельными writable volumes. Закреплённые dependency versions и image digests; vulnerability scan, SBOM, лицензии зависимостей; backup/restore и rollback runbooks. Поддержка обновления схемы без повреждения старых данных.

## 12. Пошаговая реализация — что писать и чем подтверждать

### Шаг 0. Сохранить контекст и подготовить монорепозиторий

Сделать snapshot старого прототипа, проверить Git и не затереть пользовательские изменения. Добавить docs/adr/0001-system-boundaries.md, 0002-observation-profile.md, 0003-feature-contract.md. Создать go.mod, ml/pyproject.toml и web/package.json с закреплёнными версиями после проверки инструментов. Настроить .gitignore для PCAP, data, weights, secrets. Набор данных не коммитить.

Критерий: clean install в новом окружении и test target для Go/Python. Никаких заявлений о работающей модели.

### Шаг 1. Контракты и fixtures

Написать contracts/features.md, window.schema.json, prediction.schema.json, OpenAPI. В test fixtures сохранить маленькие IPv4/IPv6 TCP/UDP/ICMP PCAP/PCAPNG, truncation, invalid timestamps, VLAN, unsupported linktype. Для каждого — независимо вычисленный expected JSON. Сгенерировать типы/валидаторы и проверить Go→JSON→Python→JSON.

Критерий: unknown schema отвергается, nan/inf и неверные единицы не проходят, int64 timestamp не теряет точность.

### Шаг 2. Offline source и decoder на Go

Source.Next(ctx) возвращает PacketMeta или EOF/error. Сначала pcap/pcapng backend, затем decoder. Отделить raw packet library от бизнес-типов. Чтение потоковое, ограничения файла и decoder budgets; не загружать целый PCAP в RAM.

Критерий: golden fixtures, malformed input не вызывает panic; fuzz parser; counters равны ожидаемым. CLI sensor replay --input ... --output windows.jsonl.

### Шаг 3. Flow tracker и window engine

FlowKey, direction resolver, bounded state map, expiry, event-time watermark, partial/gap flags. Затем host и destination_service aggregators; точные уникальные множества с лимитами, состояние превышения лимита отмечается, а не скрыто обрезается. Для роста перейти на sketches только с новой версией и измерением ошибки.

Критерий: SYN retransmission, FIN/RST, timeout, bidirectional packets, reordered packets, window boundary, partial capture, restart. Предельная память не зависит бесконтрольно от длительности записи.

### Шаг 4. Live capture и Linux-упаковка

Добавить source live, interface enumeration, явный BPF, stats polling, signal handling. Закрытие потока через context; копировать нужные метаданные до переиспользования буфера. Capability requirements документировать.

Критерий: capture на lab target видит контрольный трафик; offline и live признаки совпадают на эквивалентных полных окнах. Права проверены, потери/ошибки видны.

### Шаг 5. Spool и надёжный transport

Реализовать append/read/ack/recover, segment rotation и overflow policy. Sender с retry/jitter, batch IDs и deadline. Проверять checksum, torn write и crash между записью/ACK.

Критерий: отключение API не убивает сенсор, восстановление не дублирует события, переполнение даёт quality alert.

### Шаг 6. API, PostgreSQL и worker

SQL migrations → repository methods → ingestion validation → transaction+jobs → worker lease → prediction write. Integration tests на реальном PostgreSQL, не только mocks. Endpoint UI пока отдаёт простые JSON.

Критерий: ACK после commit, повтор batch безопасен, worker crash после infer не создаёт дубликаты. Старые jobs не блокируют live навсегда.

### Шаг 7. Лаборатория и сбор normal data

Compose target+sensor+clients+pipeline, runner и scenario configs. Начать stable/ramp/background transfer. Сохранить manifests, actual rates и PCAP только на стенде. Unit tests генератора не заменяют захват фактических пакетов.

Критерий: несколько воспроизводимых normal runs, правильная видимость, независимо проверенные counts. Затем добавить fault scenarios с capped duration/rate.

### Шаг 8. Baselines и модельный сервис

Python dataset loader, split checks, preprocessing, threshold/EWMA/IF, fit/evaluate/export CLI. Serving грузит bundle; contract tests против Go fixtures. Warmup и unsupported profile имеют явные статусы.

Критерий: одним сценарием получить normal→anomaly→incident с сохранёнными IDs и воспроизводимым результатом. Это ML-минимум, а не случайные пороги на каждом запуске.

### Шаг 9. Incident engine и интерфейс

Сначала lifecycle state machine и его тесты, затем API cards/charts. Обработать pending/degraded/empty/error states. Добавить фильтры entity/time/model, ack, export с метаданными. Проверить accessibility, keyboard navigation и длинные IPv6/filename.

Критерий M1: новый пользователь поднимает стенд по README, видит живой трафик, аномальный сценарий и объяснение сигнала; может остановить/перезапустить сервисы без потери истории.

### Шаг 10. GRU и сравнение

SequenceDataset с каузальными границами → GRUForecast → train loop → early stopping → score calibration → bundle → serving. Проверить batch/single prediction equivalence, CPU reproducibility с допусками, отсутствие label/future leakage.

Критерий M2: отчёт IF/EWMA/GRU при одном false-alert budget, incident policy и splits. Если GRU хуже, честно оставить IF default, GRU как экспериментальную; не выбирать победителя по названию архитектуры.

### Шаг 11. Нагрузка, отказоустойчивость, безопасность и пилот

Bench fixtures и live load → pprof/profiler → только измеренные оптимизации. Нагрузить ingestion и БД; soak; fault matrix; backup restore; migration and rollback; auth tests; dependency checks; shadow pilot.

Критерий M3: заполнен release checklist, привязаны отчёты к commit/model/config/hardware, известные ограничения отражены в документации. Пока gate не пройден — не называем релиз production-ready.

### Шаг 12. Классификация аномалий после минимума

Выполнить раздел 13. Не добавлять красивые вероятности в UI до оценки calibration и полного end-to-end pipeline.

## 13. Финальное расширение — классификация и вероятности

### Что классифицируем

Начальная taxonomy зависит от подтверждённых меток: benign, port_scan, single_source_dos_like, ddos_like. Эксплуатационные сбои добавляются отдельными классами только при наличии отличимых наблюдений и данных. Unknown — отказ от известного класса, а не обещание обучить модель на всех неизвестных атаках.

Для DDoS классифицируем окна destination_service, используя признаки множества источников и динамику сервиса. Для scan — host. Не заставлять одну модель угадывать класс из неподходящего scope. Для начального multi-class набора исключить неоднозначные пересечения из supervised train, но проверить на них abstention отдельно. Если реальные события многометочные — отдельный ADR и multilabel постановка.

Классификатор обучается на известных normal и attack examples. Нельзя обучить только attack classes и заставить его любой normal всплеск назвать одним из видов атак.

### Выбор модели

Первый кандидат — HistGradientBoostingClassifier на табличных оконных признаках и каузальных агрегатах короткой истории. Сравнение с logistic regression baseline. Это отдельный компонент; использование PyTorch в основной GRU остаётся. Более сложный temporal classifier или fine-tuning GRU — только если boosting недостаточен по измерениям.

Не требуется, чтобы один алгоритм решал и novelty detection, и типизацию. Detector находит отклонение; classifier предлагает известный класс. MVP classification применяется к candidate windows/инцидентам, но офлайн оценка проводится на всём pipeline: пропуск detector нельзя скрыть хорошим classifier recall.

При маленькой стоимости можно также считать classifier в shadow на всех service windows, чтобы измерить selection bias и потенциальные пропуски gate. Изменение gate политики после calibration требует новой проверки.

### Вероятности

Predict_proba/softmax сами по себе не гарантируют калибровку. Отдельный calibration split, sigmoid либо isotonic при достаточном количестве данных, multiclass схема с корректной нормировкой. Метрики: classwise reliability diagrams, Brier score, log loss, ECE с указанным биннингом и support по классам [S6].

Оценка calibration должна соответствовать тому подмножеству, где UI показывает вероятности: если классифицируем только прошедшие anomaly gate, проверяем calibration и на нём, и на полном потоке. Не перемножать anomaly_score и classifier probability: первый не является вероятностью.

Порог отказа и decision threshold выбираются на development/calibration данных, не на test. Вне поддержанного observation profile, при плохом coverage или слишком низкой уверенности возвращаем unknown/insufficient_data. Максимальный softmax и низкая энтропия не являются надёжным доказательством отсутствия OOD; проверяем withheld families и чужие сети отдельно.

Интерфейс: «Вероятный тип: DDoS-подобная активность. Оценка модели: 0,82. Версия …, профиль …». Число — пример формата, не измеренный результат. Значение относится к распределению данных, на котором проверялась модель, и может ухудшиться при сдвиге. Не писать «вероятность реальной атаки 82%» без соответствующей проверки на рабочей популяции и её class prevalence.

Вероятности нескольких окон нельзя произвольно усреднить и назвать вероятностью всего инцидента. MVP показывает вероятность выбранного окна и его время; incident-level confidence добавляется после отдельной агрегации и калибровки на incident labels.

### Приёмка классификатора

Data audit → Go extraction → label join → grouped splits → baseline → classifier → calibration → known/unknown/normal-shift evaluation → shadow mode → UI. Macro-F1, per-class precision/recall, confusion matrix, coverage versus risk при abstention, calibration, false DDoS alerts/hour, задержка всего каскада. Отдельно тест flash crowd vs overload: многим источникам и большому объёму недостаточно, чтобы доказать атаку. Если признаки не различают сценарии, показываем «необычная нагрузка», а не выдумываем уверенный класс.

## 14. Процесс разработки и контроль качества

Каждый шаг — небольшой reviewable commit: проблема → изменение → тест → проверенный результат. Сначала договориться о семантике, затем код. Не писать тесты, которые лишь повторяют реализацию: expected counters рассчитываются независимо, используются реальные фикстуры и интеграционные проверки.

CI: Go format/build/test/race, decoder fuzz smoke, Python unit+contract tests, TypeScript typecheck/build, PostgreSQL integration, container build, vulnerability/secret scan. Тяжёлые replay/soak и GPU-free training smoke — отдельный workflow. Тесты с capture capabilities запускаются только в изолированном runner; обычный CI покрывает offline source.

Целевые команды после реализации Makefile:

- make bootstrap — проверка инструментов и зависимостей;
- make test — unit/contract;
- make integration — БД и межсервисные проверки;
- make lab-up / make lab-down — стенд;
- make scenario SCENARIO=normal-ramp SEED=42;
- make dataset / make train / make evaluate — принимают явный manifest/config;
- make bench / make soak;
- make release-check — проверка артефактов и release checklist.

Фиксировать версии Python/Go/Node и lockfiles, а не ставить произвольный latest. Зависимости выбирать минимальные и поддерживаемые, проверять совместимость с Linux amd64/arm64. На каждый публичный API и schema change — контрактный тест. Новая фича не должна молча менять старые model inputs.

Перед завершением каждой сессии агент обновляет PLAN.md и docs/status.md: что сделано, какие команды прошли, что не проверено, следующий конкретный шаг. Если нет разрешённой среды для live capture, выполнить offline работы и описать точный блокер; не подменять результат симуляцией.

Курсовую пишем по артефактам продукта: схема архитектуры из ADR, определения признаков из contracts, эксперименты из manifests, таблицы из evaluation outputs. Не переписывать отчёты вручную и не придумывать показатели. Word не обновляется вместо разработки продукта.

## 15. Что должно лежать в релизе

- исходники Go/Python/web, configs, migrations, lockfiles;
- quickstart, lab compose и воспроизводимый demo;
- feature schema и golden fixtures;
- trusted model bundle с model card и отчётом качества;
- dataset manifests без выкладывания чужих данных с неясными правами;
- benchmark/fault/restore результаты с окружением;
- runbooks: install, no traffic, capture drops, backlog, ML unavailable, rollback, backup restore;
- список поддержанных observation profiles и известных ограничений;
- release notes, SBOM, лицензии и checksums.

## 16. Источники решений и ограничения проверки

Проверены страницы 06.11.2026. Выбор архитектуры и параметры выше — наши инженерные решения; ссылки подтверждают возможности инструментов и происхождение данных, а не эффективность ещё не созданной системы.

[S1] CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
[S2] CIC-DDoS2019: https://www.unb.ca/cic/datasets/ddos-2019.html
[S3] Engelen, Rimmer, Joosen. Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study: https://intrusion-detection.distrinet-research.be/WTMC2021/
[S4] Docker Compose service network_mode: https://docs.docker.com/reference/compose-file/services/#network_mode
[S5] Docker Desktop host networking limitations: https://docs.docker.com/engine/network/drivers/host/
[S6] Probability calibration, scikit-learn: https://scikit-learn.org/stable/modules/calibration.html
[S7] Docker network isolation: https://docs.docker.com/reference/compose-file/networks/
[S8] GoPacket: https://pkg.go.dev/github.com/gopacket/gopacket
[S9] PyTorch GRU: https://docs.pytorch.org/docs/stable/generated/torch.nn.GRU.html

Полные датасеты не загружались. Доступность конкретных архивов, лицензия выбранной редакции, качество label join и переносимость на наш профиль требуют data audit на шаге работы с данными.
