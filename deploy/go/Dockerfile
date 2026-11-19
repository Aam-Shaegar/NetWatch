FROM golang:1.26.11@sha256:957952ae74dc010608717144399a59a2c6e82ea03d63be1c7ff6577c5a135f93 AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY contracts/ contracts/
COPY migrations/ migrations/
COPY internal/ internal/
COPY cmd/ cmd/
RUN CGO_ENABLED=0 go build -trimpath -o /out/ ./cmd/netwatch-api ./cmd/netwatch-worker ./cmd/netwatch-probe

FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS web-build
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/index.html web/tsconfig.json ./
COPY web/src/ ./src/
RUN npm run build

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=go-build /out/ /usr/local/bin/
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=web-build /src/dist/ /srv/netwatch/web/
USER 65532:65532
CMD ["/usr/local/bin/netwatch-api"]
