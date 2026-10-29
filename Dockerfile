# Build a static binary, then ship it on nothing.
#
# The runtime image holds the binary and a CA bundle, and no shell, package
# manager or utilities. That is partly hardening and partly an argument: a
# client's security officer can see exactly what would run in their cluster.

FROM golang:1.24-alpine AS build

WORKDIR /src

# Dependencies first, so a code change does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/stathe ./cmd/stathe

# Prove the binary works before it is shipped.
RUN /out/stathe version && /out/stathe check --manifests cluster/northwind >/dev/null

FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="stathe" \
      org.opencontainers.image.description="Read-only Kubernetes security assessment" \
      org.opencontainers.image.source="https://github.com/stathe-io/stathe" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/stathe /stathe

# distroless/nonroot runs as uid 65532. stathe needs no write access anywhere.
USER nonroot:nonroot

ENTRYPOINT ["/stathe"]
CMD ["check"]
