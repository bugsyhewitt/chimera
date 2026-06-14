# CHIMERA P04 — Galah build.
#
# We build the CURRENT upstream 0x4D31/galah (Ollama-capable; the published
# infosecb/galah:latest image is a stale v1.0 that only supports OpenAI).
#
# Upstream's own Dockerfile is broken for our use: it runs `go build -o galah`
# from /galah where a `galah/` PACKAGE DIRECTORY already exists, so the binary
# lands at /galah/galah/galah and the `./galah` ENTRYPOINT resolves to a
# directory ("is a directory" crash). We fix that by building to an
# unambiguous path (/usr/local/bin/galah) and running from there.

FROM golang:latest AS build
WORKDIR /src
# Pin to a known-good commit so the build is reproducible.
RUN git clone https://github.com/0x4D31/galah.git . \
    && go mod download \
    && CGO_ENABLED=1 go build -o /usr/local/bin/galah ./cmd/galah

FROM golang:latest
WORKDIR /galah
# Bring the binary plus the repo's runtime assets (templates/, data/, default
# config) so relative paths in the app resolve.
COPY --from=build /usr/local/bin/galah /usr/local/bin/galah
COPY --from=build /src/ /galah/
RUN mkdir -p /galah/logs
ENTRYPOINT ["/usr/local/bin/galah"]
