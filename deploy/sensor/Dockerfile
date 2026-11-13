FROM golang:1.25@sha256:ce63a16e0f7063787ebb4eb28e72d477b00b4726f79874b3205a965ffd797ab2 AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download -x
COPY contracts/ contracts/
COPY migrations/ migrations/
COPY internal/ internal/
COPY cmd/ cmd/
COPY tests/fixtures/ tests/fixtures/
RUN go test -race ./... && go build -o /netwatch-sensor ./cmd/netwatch-sensor

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=build /netwatch-sensor /usr/local/bin/netwatch-sensor
ENTRYPOINT ["netwatch-sensor"]
