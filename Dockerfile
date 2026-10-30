# Build a static binary, then ship it on nothing.
#
# The runtime image holds the binary and a CA bundle, and no shell, package
# manager or utilities. That is partly hardening and partly an argument: a
# client's security officer can see exactly what would run in their cluster.

# Both base images are pinned by digest. A tag can be moved underneath a build;
# a digest cannot, and stathe's own SC-07 check says exactly this about every
# image it finds -- a tool that flags floating tags while building on one is not
# worth listening to. Dependabot keeps these current.
#
# Each digest is the image index, not one platform's manifest, so the
# linux/amd64 and linux/arm64 builds both resolve from it. Replace a pin with:
#   docker buildx imagetools inspect <image>:<tag> | grep '^Digest:'
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build

WORKDIR /src

# Dependencies first, so a code change does not re-download the module cache.
# `go mod verify` fails the build if a downloaded module differs from go.sum.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/stathe ./cmd/stathe

# Prove the binary works before it is shipped.
RUN /out/stathe version && /out/stathe check --manifests cluster/northwind >/dev/null

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.title="stathe" \
      org.opencontainers.image.description="Read-only Kubernetes security assessment" \
      org.opencontainers.image.source="https://github.com/stathe-io/stathe" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/stathe /stathe

# distroless/nonroot runs as uid 65532. stathe needs no write access anywhere.
USER nonroot:nonroot

ENTRYPOINT ["/stathe"]
CMD ["check"]
