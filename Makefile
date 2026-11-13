.PHONY: help configure bootstrap doctor test test-go test-python test-legacy build api ml web compose-check db-up db-down lab-up lab-down lab-smoke fixtures
UV ?= ./scripts/uv
help:
	@echo "configure bootstrap doctor test build api ml web compose-check db-up db-down lab-smoke lab-down"
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
