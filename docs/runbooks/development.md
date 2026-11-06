# Development quickstart

Install Go 1.25+, Python 3.14 (3.12/3.13 supported by package range), Node 22.12+ and Docker Compose.
From the repository root: `make bootstrap`, `make test`, `make build`, `make compose-check`.
`make api`: loopback port 8080; `make ml`: loopback 8000; `make web`: Vite loopback dev server.
Both health/live return 200, health/ready return 503: ingestion and trained model are not implemented.
`go run ./cmd/netwatch-sensor -validate window contracts/examples/window.valid.json` checks contracts.
`make db-up` starts local PostgreSQL on 54329; `make db-down` preserves its volume.
`make lab-smoke` builds an isolated benign HTTP test and records traffic under a unique directory in data/runs/.
Each run creates a separate Compose project and terminates its containers on exit.
`make lab-down` stops owned lab containers. No host interface capture occurs in bootstrap.
Raw data, .env and models are ignored. Actual preparation checks are in docs/status.md.
Next task: implement Go offline capture/decode using tests/fixtures/pcap and contract tests.

When uv is absent, bootstrap installs pinned uv in .tools/uv; scripts/uv is the portable wrapper.

Lab PCAP uses full packet length only for synthetic HTTP traffic. Production sensor will discard payload.
