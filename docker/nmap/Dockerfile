# Obraz skanera: nmap + curl + jq (PoC `make poc`) + binarka `asi` (silnik w Go).
# Kontekst buildu = root repo (patrz docker-compose.yml, .dockerignore).

FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi

FROM alpine:3.20
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    bash \
    curl \
    jq
COPY --from=build /out/asi /usr/local/bin/asi

# /work = katalog roboczy asi (targets/ i results/ podpiete z repo)
WORKDIR /work

ENTRYPOINT ["sleep", "infinity"]
