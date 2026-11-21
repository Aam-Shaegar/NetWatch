.PHONY: help configure bootstrap doctor test test-go test-python test-legacy build api ml web compose-check db-up db-down lab-up lab-down lab-smoke fixtures
UV ?= ./scripts/uv
help:
	@echo "Setup:      bootstrap configure doctor"
	@echo "Build:      build test compose-check"
	@echo "Services:   work work-status work-logs work-stop cli (local dev: db-up migrate api worker ml web)"
	@echo "Capture:    lab-up lab-down lab-smoke live-smoke fixtures"
	@echo "Models:     collect dataset train compare v1-data v1-train"
	@echo "Checks:     test test-e2e test-acceptance collection-smoke server-smoke bench operations test-anomalies"
	@echo "V1 ML:      test-find test-classify test-full"
configure:
	python3 scripts/configure.py
bootstrap:
	python3 scripts/bootstrap_tools.py
	$(UV) sync --project ml --locked
	cd web && npm ci
	go mod download
	$(MAKE) configure

doctor:
	python3 scripts/doctor.py
test: test-go test-python test-legacy

test-go:
	go test -race ./...
test-python:
	$(UV) run --project ml --locked pytest ml/tests

test-legacy:
	python3 -m unittest discover -s tests -v
build:
	go build ./cmd/...
	cd web && npm run build
api:
	go run ./cmd/netwatch-api
ml:
	$(UV) run --project ml --locked uvicorn netwatch_ml.serving.app:app --host 127.0.0.1 --port 8000
web:
	cd web && npm run dev
compose-check: configure
	docker compose --env-file .env -f deploy/compose.yaml config --quiet
	docker compose -f deploy/lab/compose.yaml config --quiet
	docker compose -f deploy/lab/compose.yaml -f deploy/lab/collection.yaml config --quiet
	docker compose -f deploy/lab/compose.yaml -f deploy/lab/operations.yaml config --quiet
	python3 scripts/stack.py check
db-up: configure
	docker compose --env-file .env -f deploy/compose.yaml up -d --wait
db-down:
	docker compose --env-file .env -f deploy/compose.yaml down
lab-up:
	mkdir -p data/runs/current
	docker compose -f deploy/lab/compose.yaml up -d --build target recorder
lab-down:
	docker compose -f deploy/lab/compose.yaml down
lab-smoke:
	python3 scripts/lab_smoke.py
fixtures:
	$(UV) run --project ml --locked python scripts/generate_fixtures.py

.PHONY: live-smoke
live-smoke:
	python3 scripts/live_smoke.py

.PHONY: server-smoke migrate worker
server-smoke:
	python3 scripts/server_smoke.py
migrate:
	go run ./cmd/netwatch-api --migrate-only
worker:
	go run ./cmd/netwatch-worker

.PHONY: collect dataset collection-smoke
collect:
	python3 scripts/collect_dataset.py $(COLLECT_ARGS)
dataset:
	$(UV) run --project ml --locked python -m netwatch_ml.data.dataset "$(COLLECTION)" "$(OUTPUT)"
collection-smoke:
	$(UV) run --project ml --locked python scripts/collection_smoke.py

.PHONY: work work-status work-logs work-stop cli train train-local test-e2e test-acceptance
WORK_ENV ?= .env.work
work:
	python3 scripts/stack.py work start --env "$(WORK_ENV)"
work-status:
	python3 scripts/stack.py work status --env "$(WORK_ENV)"
work-logs:
	python3 scripts/stack.py work logs --env "$(WORK_ENV)"
work-stop:
	python3 scripts/stack.py work stop --env "$(WORK_ENV)"
CLI_OUTPUT ?= bin/netwatch
cli:
	go build -trimpath -o "$(CLI_OUTPUT)" ./cmd/netwatch
train:
	python3 scripts/stack.py train "$(DATASET)" "$(OUTPUT)"

train-local:
	$(UV) run --project ml --locked python -m netwatch_ml.training.baselines "$(DATASET)" "$(OUTPUT)"

.PHONY: compare
compare:
	$(UV) run --project ml --locked python -m netwatch_ml.training.forecast "$(DATASET)" "$(COLLECTION)" "$(BASELINE)" "$(OUTPUT)"

.PHONY: bench operations spool-disk-smoke
bench:
	go test ./internal/window -run '^$$' -bench BenchmarkServiceWindows -benchtime=500000x -count=3

OPERATIONS_SECONDS ?= 180
OPERATIONS_LATENESS ?= 1s
operations:
	$(UV) run --project ml --locked python scripts/operations.py "$(ARTIFACT)" --seconds "$(OPERATIONS_SECONDS)" --lateness "$(OPERATIONS_LATENESS)"

spool-disk-smoke:
	python3 scripts/spool_disk_smoke.py

.PHONY: test-anomalies
ANOMALY_MANIFEST ?= data/holdout/anomalies/manifest.json
ANOMALY_SERVICE ?= artifacts/tcp-service-patterns-v2
ANOMALY_FORECAST ?= artifacts/step10-gru
ANOMALY_TRAINING ?= data/processed/step7-16d38550a4d3/manifest.json
ANOMALY_REPORT ?= outputs/anomaly-holdout.json
ANOMALY_MODE ?=

test-anomalies:
	$(UV) run --project ml --locked python benchmarks/independent.py $(ANOMALY_MODE) "$(ANOMALY_MANIFEST)" "$(ANOMALY_SERVICE)" "$(ANOMALY_FORECAST)" "$(ANOMALY_TRAINING)" "$(ANOMALY_REPORT)"

E2E_ARTIFACT ?= artifacts/tcp-service-patterns-v2
E2E_REPORT ?= outputs/work-e2e.json
E2E_POLICY ?= v1
test-e2e:
	python3 tests/e2e/work_stack.py "$(E2E_ARTIFACT)" "$(E2E_REPORT)" --policy "$(E2E_POLICY)"

ACCEPTANCE_MANIFEST ?= data/holdout/detection/manifest.json
ACCEPTANCE_REPORT ?= outputs/detection-acceptance.json
test-acceptance:
	python3 benchmarks/detection_acceptance.py "$(ACCEPTANCE_MANIFEST)" "$(E2E_ARTIFACT)" "$(ACCEPTANCE_REPORT)"

.PHONY: v1-data v1-train test-find test-classify test-full test-pipeline
V1_MANIFEST ?= data/holdout/v1/manifest.json
V1_DATA ?= data/processed/v1/data.jsonl
V1_TEST_DATA ?= $(V1_DATA)
V1_PIPELINE_DATA ?= $(V1_TEST_DATA)
V1_MODELS ?= artifacts/v1
V1_REPORT_DIR ?= outputs/v1
V1_SEED ?= 42
V1_MAX_FPR ?= 0.02
V1_MAX_UNKNOWN_ACCEPTANCE ?= 0.10
V1_SENSOR ?= bin/netwatch-sensor
V1_CATALOG ?= bin/netwatch-catalog
V1_RUN = $(UV) run --project ml --locked python -m netwatch_ml.v1

v1-data:
	mkdir -p "$(dir $(V1_SENSOR))" "$(dir $(V1_CATALOG))"
	go build -trimpath -buildvcs=false -o "$(V1_SENSOR)" ./cmd/netwatch-sensor
	go build -trimpath -buildvcs=false -o "$(V1_CATALOG)" ./cmd/netwatch-catalog
	$(V1_RUN) prepare "$(V1_MANIFEST)" "$(V1_DATA)" --sensor "$(V1_SENSOR)" --catalogue "$(V1_CATALOG)"

v1-train:
	$(V1_RUN) train "$(V1_DATA)" "$(V1_MODELS)" --seed "$(V1_SEED)" --max-fpr "$(V1_MAX_FPR)" --max-unknown-acceptance "$(V1_MAX_UNKNOWN_ACCEPTANCE)"

test-find:
	$(V1_RUN) evaluate find "$(V1_TEST_DATA)" "$(V1_MODELS)" "$(V1_REPORT_DIR)/find$(if $(MODEL),-$(MODEL)).json" $(if $(MODEL),--model "$(MODEL)")

test-classify:
	$(V1_RUN) evaluate classify "$(V1_TEST_DATA)" "$(V1_MODELS)" "$(V1_REPORT_DIR)/classify$(if $(MODEL),-$(MODEL)).json" $(if $(MODEL),--model "$(MODEL)")

test-full: test-pipeline

test-pipeline:
	$(V1_RUN) evaluate pipeline "$(V1_PIPELINE_DATA)" "$(V1_MODELS)" "$(V1_REPORT_DIR)/pipeline$(if $(MODEL),-$(MODEL)).json" $(if $(MODEL),--model "$(MODEL)")
