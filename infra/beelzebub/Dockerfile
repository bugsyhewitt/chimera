# CHIMERA P10a — Beelzebub build.
#
# No usable prebuilt image: `mariocandela/beelzebub:latest` is referenced in the
# upstream docs but is NOT pullable from Docker Hub (pull access denied / no tags
# via the registry API as of 2026-06). So we build from the upstream git context,
# mirroring how P04 handled Galah.
#
# Upstream note: github.com/mariocandela/beelzebub 301-redirects to the
# github.com/beelzebub-labs/beelzebub v3 fork (Go module
# `github.com/beelzebub-labs/beelzebub/v3`). git clone follows the redirect, so we
# keep the canonical mariocandela URL here for provenance. The entrypoint is the
# cobra `run` subcommand; core config + services dir are passed via flags at
# runtime in docker-compose (defaults are ./configurations/beelzebub.yaml and
# ./configurations/services/).

FROM golang:alpine AS build
RUN apk add --no-cache git
WORKDIR /src
# Clone upstream (canonical URL redirects to beelzebub-labs/beelzebub).
RUN git clone https://github.com/mariocandela/beelzebub.git . \
    && go mod download \
    && CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/beelzebub .

# Tiny runtime image. We do NOT bake configs in — they are bind-mounted from
# infra/beelzebub/ so the lead can edit the decoy without a rebuild.
FROM alpine:latest
RUN apk add --no-cache ca-certificates \
    && mkdir -p /beelzebub/logs
WORKDIR /beelzebub
COPY --from=build /usr/local/bin/beelzebub /usr/local/bin/beelzebub
ENTRYPOINT ["/usr/local/bin/beelzebub", "run"]
