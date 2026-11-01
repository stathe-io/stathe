# Install

> **Private beta.** `preflight`, `check`, `diff`, `report`, `baseline` and
> `compliance` work today. A release is a tag, and the pipeline builds
> everything from it: the image at `ghcr.io/stathe-io/stathe` for `linux/amd64`
> and `linux/arm64`, static binaries with `SHA256SUMS`, an SBOM, build
> provenance and a keyless signature — verify them with the commands in
> [SECURITY.md](../SECURITY.md). The `v0.3.0` tag predates that pipeline: it was
> pushed by hand and is `arm64` only, so use a later tag.
>
> Commands in this file assume `stathe` is on your `PATH`; use
> `go run ./cmd/stathe` from inside this repository instead.

## From source

```sh
git clone https://github.com/stathe-io/stathe
cd stathe
go build -ldflags "-X main.version=$(git describe --tags --always)" -o stathe ./cmd/stathe
```

Go 1.26 or newer: the patched `golang.org/x/net` requires it. There are no
runtime dependencies: the result is a single static binary.

## Container

```sh
make image                 # builds stathe:$(git describe --tags) on distroless
make image-save            # writes a tarball of it for an air-gapped host
```

The runtime image holds the binary and a CA bundle. No shell, no package
manager, nothing else — partly hardening, and partly so a client's security
officer can see exactly what would run.

```sh
docker run --rm \
  --mount type=bind,src=$HOME/.kube/config,dst=/kube/config,readonly \
  --user "$(id -u):$(id -g)" \
  -e KUBECONFIG=/kube/config \
  stathe:v0.3.2 check
```

Two details worth copying rather than simplifying:

- **`--mount`, not `-v`.** With `-v`, Docker silently creates a root-owned
  empty directory when the source path does not exist, and the run then fails
  with `is a directory` — pointing at the wrong problem. `--mount` fails
  immediately, naming the path it could not find.
- **`--user`.** A kubeconfig is usually mode 600 and the image runs as uid
  65532, so without this the file is unreadable. stathe needs no write access
  anywhere, so running as yourself costs nothing.

Both mistakes are recognised: if the kubeconfig cannot be read, the error says
which path was tried and which of the two it looks like.

Running the binary directly on a node, with no container runtime involved, is
simpler still — and on an air-gapped host it is usually the smoothest path.


## Verify what you run

Releases are signed without a long-lived key and carry an SBOM and build
provenance. The commands, and the [threat model](threat-model.md) behind
them, are in [SECURITY.md](../SECURITY.md).
