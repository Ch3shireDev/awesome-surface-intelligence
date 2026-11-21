# Obraz skanera: nmap + httpx + nuclei + curl + jq (PoC `make poc`) + binarka `asi` (silnik w Go).
# Kontekst buildu = root repo (patrz docker-compose.yml, .dockerignore).

FROM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/asi ./cmd/asi

FROM alpine:3.20
# mirror Alpine bywa bardzo wolny (zdarzaly sie przerwy): 3 proby z przerwa
RUN for i in 1 2 3; do \
      apk add --no-cache nmap nmap-scripts bash curl jq && exit 0; \
      echo "apk add: proba $i nieudana, ponawiam"; sleep 10; \
    done; exit 1
COPY --from=build /out/asi /usr/local/bin/asi

# httpx (etap http, SEC-4) i nuclei (etap signatures, SEC-5): oficjalne wydania ProjectDiscovery
# (MIT), wersje przypiete, sumy SHA-256 sprawdzane z pliku checksums wydania.
# Architektura z `uname -m`, bo builder bez buildx nie ustawia TARGETARCH.
ARG HTTPX_VERSION=1.12.0
ARG NUCLEI_VERSION=3.11.1
RUN set -eu; \
    case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "arch?"; exit 1 ;; esac; \
    cd /tmp; \
    for t in "httpx $HTTPX_VERSION" "nuclei $NUCLEI_VERSION"; do \
      set -- $t; f="${1}_${2}_linux_${arch}.zip"; \
      curl -fsSLO "https://github.com/projectdiscovery/$1/releases/download/v$2/$f"; \
      curl -fsSL "https://github.com/projectdiscovery/$1/releases/download/v$2/${1}_${2}_checksums.txt" | grep " $f\$" | sha256sum -c -; \
      unzip -o -q "$f" "$1" -d /usr/local/bin; rm -f "$f"; \
    done; \
    httpx -version >/dev/null 2>&1; nuclei -version >/dev/null 2>&1

# nasze sygnatury (podpiete tez z repo w compose, wiec edycja nie wymaga przebudowy)
COPY signatures /work/signatures

# /work = katalog roboczy asi (targets/ i results/ podpiete z repo)
WORKDIR /work

ENTRYPOINT ["sleep", "infinity"]
