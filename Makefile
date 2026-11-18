.PHONY: help configure bootstrap doctor test test-go test-python test-legacy build api ml web compose-check db-up db-down lab-up lab-down lab-smoke fixtures
UV ?= ./scripts/uv
help:
	@echo "Setup:      bootstrap configure doctor"
	@echo "Build:      build test compose-check"
	@echo "Services:   db-up db-down migrate api worker ml web"
	@echo "Capture:    lab-up lab-down lab-smoke live-smoke fixtures"
	@echo "Models:     collect dataset train compare"
	@echo "Checks:     collection-smoke server-smoke spool-disk-smoke bench operations test-anomalies"
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

.PHONY: train
train:
	$(UV) run --project ml --locked python -m netwatch_ml.training.baselines "$(DATASET)" "$(OUTPUT)"

.PHONY: compare
compare:
	$(UV) run --project ml --locked python -m netwatch_ml.training.forecast "$(DATASET)" "$(COLLECTION)" "$(BASELINE)" "$(OUTPUT)"

.PHONY: bench operations spool-disk-smoke
bench:
	go test ./internal/window -run '^$$' -bench BenchmarkServiceWindows -benchtime=500000x -count=3

OPERATIONS_SECONDS ?= 180
operations:
	$(UV) run --project ml --locked python scripts/operations.py "$(ARTIFACT)" --seconds "$(OPERATIONS_SECONDS)"

spool-disk-smoke:
	python3 scripts/spool_disk_smoke.py

.PHONY: test-anomalies
ANOMALY_MANIFEST ?= data/holdout/anomalies/manifest.json
ANOMALY_SERVICE ?= artifacts/tcp-service-patterns-v2
ANOMALY_FORECAST ?= artifacts/step10-gru
ANOMALY_TRAINING ?= data/processed/step7-16d38550a4d3/manifest.json
ANOMALY_REPORT ?= outputs/anomaly-holdout.json

test-anomalies:
	$(UV) run --project ml --locked python benchmarks/independent.py "$(ANOMALY_MANIFEST)" "$(ANOMALY_SERVICE)" "$(ANOMALY_FORECAST)" "$(ANOMALY_TRAINING)" "$(ANOMALY_REPORT)"
