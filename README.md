<p align="center">
  <img src="docs/banner.png" alt="stathe" width="760">
</p>

<p align="center">
  An audit-ready Kubernetes assessment you can hand to a regulator.
  Read-only, one command, nothing installed in the cluster.
</p>

<p align="center">
  <a href="#getting-started">Get started</a> &middot;
  <a href="#checks">Checks</a> &middot;
  <a href="cluster/readonly-rbac.yaml">Permissions</a> &middot;
  <a href="#in-a-pipeline">Pipelines</a>
</p>

Six checks, against a live cluster or a directory of manifests. Clone this
repository and the output below is the output you get — `cluster/northwind` is
a deliberately broken demo cluster that ships with it:

```console
$ stathe check --manifests cluster/northwind --summary
Assessed 17 resources in cluster/northwind

SC-01   high      3  No network separation between workloads
SC-04   high      1  Credentials stored in plain configuration
SC-05   high      6  Container runs with excessive privileges
                  3× northwind-tracking/deployment/tracking
                  1× northwind-orders/deployment/orders
                  1× northwind-orders/deployment/postgres
                     and 1 more
SC-06   high      2  Cluster-admin granted outside the platform's own bindings
SC-07   high      4  Workload uses a mutable image tag
SC-09   low       4  Workload has no resource limits

20 findings: 9 high, 7 medium, 4 low
```

Kubescape runs hundreds of checks. Trivy finds every CVE in your images. Both
are good, free, and broader than this. stathe is for the part they leave to
you: turning a scan into an assessment somebody else will accept as evidence.

- **Permissions a client approves in advance.** Ten resource types, one verb,
  in [one file](cluster/readonly-rbac.yaml) short enough for a security officer
  to read before the assessment starts. No `get`, no `watch`, no secrets, no
  `exec`.
- **Nothing left out quietly.** Every filter prints what it skipped and why,
  and every accepted risk stays in the report with a reason and an expiry date.
  A run that reports 17 while it suppressed 2 is the one an auditor catches.
- **Comparable next quarter.** The same cluster produces the same document, so
  `stathe diff` shows only what actually changed — and never counts an accepted
  risk as a fix.
- **Honest about its own limits.** It reads configuration. It does not attack
  anything and cannot tell you what an attacker would manage, and the report
  says that on the cover rather than implying a certification.

One static binary, no runtime dependencies, which is usually the only thing
that works in an environment with no internet.

---

## What stathe is for

A consultant or security officer who has one day in a client's cluster and
needs to leave behind something the client can act on. stathe is built around
that day, not around the scan:

1. `preflight` the day before, so nobody finds a missing permission live.
2. `check` with a permission set the client approved in advance.
3. `report` as a document an auditor will accept, with NIS2, DORA and ISO 27001
   references.
4. `baseline` as reviewed files the client applies in their own change window.

A general scanner can run the checks. The assessment around them is what stathe
adds.

---

## Why six checks

A fully patched image, in a flat network, with a service account bound to
`cluster-admin`, is still one bad afternoon. These six are about configuration
rather than about a CVE count, and "reachable according to the configuration"
is the strongest claim stathe makes.

A scan that returns everything returns nothing actionable. Someone still has to
decide which twenty of the four hundred matter. stathe ships that decision —
and prints what the decision cost, because a filter you cannot see and a clean
cluster look identical:

```console
2 findings: 1 high, 1 medium, 0 low

NOT ASSESSED (1, filtered before the checks ran)
  clusterrolebinding/cluster-admin grants cluster-admin to group system:masters
      Kubernetes or the distribution binds this identity itself; the team cannot remove it
```

A third section, `NOTED`, is for what stathe can see but cannot judge: a
`ValidatingAdmissionPolicy` mentioning images is said plainly, and the SC-07
findings stay exactly as they were. stathe reads neither CEL nor Rego, so it
does not get to decide that something else already handles a finding. That
decision is yours, and [`.stathe.yaml`](docs/accepted-risk.md) is where it goes.

---

## Install

> **Private beta.** `preflight`, `check`, `diff`, `report`, `baseline` and
> `compliance` work today. A release is a tag, and the pipeline builds
> everything from it: the image at `ghcr.io/stathe-io/stathe` for `linux/amd64`
> and `linux/arm64`, static binaries with `SHA256SUMS`, an SBOM, build
> provenance and a keyless signature — verify them with the commands in
> [SECURITY.md](SECURITY.md). The `v0.3.0` tag predates that pipeline: it was
> pushed by hand and is `arm64` only, so use a later tag.
>
> Commands in this file assume `stathe` is on your `PATH`; use
> `go run ./cmd/stathe` from inside this repository instead.

### From source

```sh
git clone https://github.com/stathe-io/stathe
cd stathe
go build -ldflags "-X main.version=$(git describe --tags --always)" -o stathe ./cmd/stathe
```

Go 1.26 or newer: the patched `golang.org/x/net` requires it. There are no
runtime dependencies: the result is a single static binary.

### Container

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
  stathe:v0.3.1 check
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

---

### Verify what you run

Releases are signed without a long-lived key and carry an SBOM and build
provenance. The commands, and the [threat model](docs/threat-model.md) behind
them, are in [SECURITY.md](SECURITY.md).

---

## Getting started

### 1. Approve the access

Hand [`cluster/readonly-rbac.yaml`](cluster/readonly-rbac.yaml) to whoever owns
the cluster before anything runs. It is the whole permission set — ten resource
types, one verb — and it is commented for the person who has to approve it. No
`get`, no `watch`, no `log`, no `exec`, and no access to Secrets at all.

```sh
kubectl apply -f cluster/readonly-rbac.yaml

# verify rather than believe it
kubectl auth can-i --list --as=system:serviceaccount:stathe:stathe
kubectl auth can-i get secrets --as=system:serviceaccount:stathe:stathe   # no
```

ConfigMaps are the one place to be precise: Kubernetes cannot list key names
alone, so each ConfigMap arrives in full and the values reach the machine
running stathe. The code keeps the keys and discards the values as each object
is parsed — a few lines in `internal/scan/cluster.go`, short enough to read
before approving the run.

### 2. Confirm it will work

```sh
stathe preflight --context production
```

Asks the API server what this account may actually do, using
`SelfSubjectAccessReview`, and names the ingress controller, CNI and GitOps
tool it finds. Exits non-zero on a no-go with the missing permission named.

Run it the day before an assessment. Discovering a missing permission with four
of someone's engineers in the room costs everyone a morning.

### 3. Assess

```sh
stathe check --context production
```

Nothing is written, nothing restarts, nothing leaves your network.

No cluster to hand? Point it at manifests instead:

```sh
stathe check --manifests ./k8s
```

---

## Commands

| Command | What it does |
|---|---|
| `stathe preflight` | Verifies access and identifies the platform, before the day |
| `stathe check` | Assesses a live cluster or a directory of manifests |
| `stathe diff` | Compares two assessments: what was fixed, what is new, what was accepted rather than fixed |
| `stathe report` | Turns findings into a document, with an optional regulatory mapping |
| `stathe baseline` | Writes the configuration that closes the findings, and applies none of it |
| `stathe compliance` | Which NIS2 measures these checks evidence, and the four they cannot |

### `stathe check`

| Flag | Meaning |
|---|---|
| `--context NAME` | Assess a live cluster. Omit to use the current kubectl context |
| `--manifests DIR` | Assess files on disk, with no cluster at all |
| `--summary` | One line per check instead of one per finding |
| `--json` | Emit the assessment as a [JSON document](docs/evidence.md) |
| `--framework NAME` | Annotate each finding with the obligation it evidences |
| `--fail-on LEVEL` | Exit 1 when a finding at this severity or above remains |
| `--exceptions DIR` | Where to look for `.stathe.yaml` |
| `--platform-namespaces NS,NS` | Namespaces belonging to whoever runs the platform rather than to the team being assessed, on top of the `kube-*` defaults |

#### `--summary`

One line per check, and under it what the findings have in common — only when
grouping actually reduces the problem. For SC-07 that grouping is by image, not
by workload: eighteen findings from three charts are three decisions. It ends
with the commands that follow it.

#### `--platform-namespaces`

A real cluster runs a GitOps controller, a policy engine and a runtime-security
agent, and those are not the team's findings. stathe only knows the `kube-*`
namespaces by default, so name the rest:

```sh
stathe check --context production --platform-namespaces fleet-system,kyverno,falco
```

Their resources are left out, counted, listed under `NOT ASSESSED` with the
reason that you declared them, and recorded in the document. This is a statement
about **scope**; a statement about **risk** belongs in
[`.stathe.yaml`](docs/accepted-risk.md).

### `stathe diff`

The retest. "We fixed it" is a claim; a diff against the assessment that found
it is evidence — and it never counts a risk that moved into `.stathe.yaml` as a
fix. [docs/evidence.md](docs/evidence.md) has the output, `--fail-on-new`, and
the JSON document both sides are read from.

### `stathe report`

```sh
stathe report --findings findings.json \
  --client "Acme B.V." --author "Your Name" --email "you@example.com" \
  --environment "production" --framework nis2 --out report.html
```

A cover, a severity summary, one card per finding with its affected resources,
and — with `--framework` — a section grouping findings by article. The cover
names the version of stathe and the assessment it was rendered from.

`--client`, `--author` and `--email` are required and have no defaults: a client
who finds someone else's contact details on their assessment has every reason to
distrust the rest of it.

For a PDF: `google-chrome --headless=new --no-pdf-header-footer
--print-to-pdf=report.pdf report.html`.

### `stathe baseline`

```sh
stathe baseline --context production --ingress-namespace ingress-nginx --out ./fix
```

Writes files and applies nothing. Your pipeline applies them, after your
review, in your change window.

The output is split in two, because the halves carry very different risk:

**`warn/` — safe to apply now.** Pod Security Admission labels in `warn` and
`audit` mode. They report violations and block nothing; every workload running
today keeps running. Enforcement is deliberately absent from these files, not
even commented out — a blocking label one keystroke from live makes "this file
is harmless" unprovable.

**`enforcing/` — needs a change window.** NetworkPolicies. These are live the
moment they land; NetworkPolicy has no audit mode, so there is no way to
preview it against real traffic. Ingress only: a default-deny on egress also
blocks DNS and fails in ways that look like an application bug for the first
twenty minutes. Each file carries its own rollback command, for whoever is
reading it at 23:00.

```sh
kubectl delete networkpolicy -A -l stathe.io/generated=true
```

---

## In a pipeline

`check` exits 0 by default, even with findings. A tool that starts breaking
builds the day somebody upgrades it gets deleted from the pipeline, so failing
is something you opt into.

```sh
stathe check --manifests ./k8s --fail-on high
```

`--fail-on` takes `high`, `medium`, `low` or `none`.

> Pin the image by digest in a pipeline you care about. A tag can be moved; a
> digest cannot, and stathe's own `SC-07` check would flag the tag — the
> Dockerfile here pins its own base images the same way, and CI fails if either
> drifts back to a tag.
>
> ```sh
> docker buildx imagetools inspect ghcr.io/stathe-io/stathe:v0.3.1 | grep '^Digest:'
> ```

### GitHub Actions

```yaml
- name: Assess the manifests
  run: |
    docker run --rm -v "$PWD:/work:ro" \
      ghcr.io/stathe-io/stathe:v0.3.1 \
      check --manifests /work/k8s --fail-on high
```

### GitLab CI

```yaml
stathe:
  image: ghcr.io/stathe-io/stathe:v0.3.1
  script:
    - stathe check --manifests ./k8s --fail-on high
```

---

## Accepted risk

Some findings are true and are going to stay: a runtime-security agent has to
mount the host filesystem. `.stathe.yaml` records that decision — the finding
stays in the report, under its own heading, with a reason and an expiry date,
and comes back by itself when the date passes. An entry without both is
refused.

[docs/accepted-risk.md](docs/accepted-risk.md) has the file format and the
cases that actually come up.

---

## Checks

IDs are `SC-nn`, for stathe check. They are stable: an ID never changes meaning
and is never reused, because a previous report, a `.stathe.yaml` and a ticket
title all refer to it. The numbering has gaps where checks are planned but not
written.

| ID | Check | What it catches | Severity |
|---|---|---|---|
| `SC-01` | Network separation | Namespaces with no NetworkPolicy, where any pod reaches any other pod | high |
| `SC-04` | Plaintext credentials | ConfigMap keys that *end* in a credential word (`DB_PASSWORD`, `client-secret`, `STRIPE_API_KEY`), never ones that merely contain it (`SECRET_SCANNER_ENABLED` is a feature flag) | high |
| `SC-05` | Workload privilege | Privileged containers, missing `securityContext`, and host mounts ranked by what they are worth: a container runtime socket or the kubelet's credentials are control of the node, `/proc` is not | high / medium |
| `SC-06` | Cluster-admin bindings | Any subject granted full control — service accounts, users, and aggregate groups such as `system:authenticated` — whether through `cluster-admin` itself or a ClusterRole that wildcards every verb, resource and API group under another name. The control plane's own identities are excluded and listed under `NOT ASSESSED` | high |
| `SC-07` | Image provenance | Floating tags like `:latest` (high), and tags that are not digests (medium) | high / medium |
| `SC-09` | Resource limits | Containers with no memory limit, where one workload starves a node | low |

Severity is the severity for a production platform, not a generic score. Every
finding carries why it matters and the next step.

They are read from Deployments, StatefulSets, DaemonSets, **Jobs, CronJobs and
bare Pods**. That last group matters more than it sounds: a CI system that
starts a build pod per job is often running the most privileged workload on the
cluster, and it belongs to no Deployment. Pods a listed controller created are
dropped on parse — they are that controller's pod template with a generated
name, so reporting them is one finding twice.

One workload with three host mounts is one finding, worded around the worst
path with the others listed. One image reused across a chart's deployments is
one row in the output, with the workloads under it — while the JSON document
keeps them separate, because each is evidence about its own resource and
`stathe diff` has to tell them apart.

### Not covered yet

`SC-02` a scan step in CI, `SC-03` known CVEs in running images, `SC-08`
signature verification, `SC-10` API audit logging. The gaps in the numbering
are these.

---

## Regulatory mapping

Every finding carries the obligation it is evidence about, under NIS2
(Article 21(2)), DORA and ISO/IEC 27001:2022 Annex A.

```sh
stathe check --context production --framework nis2
stathe compliance
```

`stathe compliance` prints coverage of NIS2 Article 21(2) — six of the ten
measures, **and the four it cannot evidence**: incident handling, assessing
effectiveness, cyber hygiene and training, and multi-factor authentication.
Those are organisational, and a coverage number that hides them is worth less
than one that does not. stathe does not certify, attest or determine
compliance, and the report says so on its own face.

---

## The demo cluster

"Northwind Logistics": four services across three namespaces with seven
deliberate weaknesses, so the tool can be demonstrated without borrowing
anyone's production. **Do not apply these manifests to a cluster you care
about.**

```sh
make up        # k3d cluster with Traefik, plus the demo app
make findings  # what stathe makes of it
make down
```

[`cluster/attack.md`](cluster/attack.md) proves each weakness by hand — reach
the database from the web pod, read the password out of a ConfigMap, escape the
privileged container — then applies the baseline and closes them.

Working on stathe itself: [docs/development.md](docs/development.md).

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

A finding it gets wrong is worth more than one it gets right —
[open an issue](https://github.com/stathe-io/stathe/issues).
