<p align="center">
  <img src="docs/banner.png" alt="stathe" width="760">
</p>

<p align="center">
  A read-only Kubernetes assessment. One command, nothing installed in the
  cluster, nothing changed.
</p>

<p align="center">
  <a href="#getting-started">Get started</a> &middot;
  <a href="#checks">Checks</a> &middot;
  <a href="cluster/readonly-rbac.yaml">Permissions</a> &middot;
  <a href="#in-a-pipeline">Pipelines</a>
</p>

> **Private beta.** `preflight`, `check`, `diff`, `report`, `baseline` and
> `compliance` work today. The image is published at
> `ghcr.io/stathe-io/stathe`; the `v0.3.0` tag there was pushed by hand and is
> `linux/arm64` only, so on an amd64 host build from source or wait for the
> next release, which the pipeline publishes for both architectures with
> binaries, checksums, an SBOM and a signature.
> The commands below assume `stathe` is on your `PATH`; use
> `go run ./cmd/stathe` while you are in this repository.

```console
$ stathe check --context production --summary
Assessed 70 resources in production

SC-01   high      3  No network separation between workloads
SC-04   high      1  Credentials stored in plain configuration
SC-05   high      5  Container runs with excessive privileges
SC-06   high      2  Cluster-admin granted outside the platform's own bindings
SC-07   high      4  Workload uses a mutable image tag
SC-09   low       4  Workload has no resource limits

19 findings: 9 high, 6 medium, 4 low

Nothing was changed. This command only reads.
```

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

kubescape runs hundreds. Trivy finds every CVE in your images. Both are good,
and stathe does not try to beat them at it.

These six are about configuration rather than about a CVE count. A fully
patched image, in a flat network, with a service account bound to
`cluster-admin`, is still one bad afternoon.

What stathe reads is the configuration as it stands. It does not attack
anything, does not try to reach anything, and cannot tell you what an attacker
would actually manage to do: that takes a test against the running system, and
this is not that tool. "Reachable according to the configuration" is the
strongest claim in here, and the report says so on the cover.

A scan that returns everything returns nothing actionable. Someone still has to
decide which twenty of the four hundred matter. stathe ships that decision
instead of the raw list: the platform's own namespaces and the control plane's
own bindings are filtered out before the checks run.

Every one of those exclusions is printed, under `NOT ASSESSED`, with a count
and a reason:

```console
2 findings: 1 high, 1 medium, 0 low

NOT ASSESSED (1, filtered before the checks ran)
  clusterrolebinding/cluster-admin grants cluster-admin to group system:masters
      Kubernetes or the distribution binds this identity itself; the team cannot remove it
```

A filter you cannot see is worse than no filter: a clean result and a quiet
tool look identical. With `--json` the same exclusions are a `not_assessed`
section of the document, so a pipeline cannot drop them either.

A third section, `NOTED`, is for what stathe can see but cannot judge. If the
cluster has a `ValidatingAdmissionPolicy` that mentions images, that is said
plainly — and the SC-07 findings stay exactly as they were, at the same risk.
stathe does not read CEL, Kyverno's language or Rego, so it does not get to
decide that something else already handles a finding. Deciding that is your
job, and recording the decision is what [`.stathe.yaml`](docs/accepted-risk.md)
is for.

---

## Install

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
make image                 # builds stathe:v0.3.0 on distroless
make image-save            # writes stathe-v0.3.0.tar.gz for an air-gapped host
```

The runtime image holds the binary and a CA bundle. No shell, no package
manager, nothing else — partly hardening, and partly so a client's security
officer can see exactly what would run.

```sh
docker run --rm \
  --mount type=bind,src=$HOME/.kube/config,dst=/kube/config,readonly \
  --user "$(id -u):$(id -g)" \
  -e KUBECONFIG=/kube/config \
  stathe:v0.3.0 check
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
the cluster before anything runs. It is the whole permission set: ten resource
types, one verb. One of them, `validatingadmissionpolicies`, is optional —
without it stathe simply cannot tell you that an admission policy may already
enforce what a finding asks for.

`pods` is in there for the pods no controller created. A CI system that starts
a build pod per job is often running the most privileged workload on the
cluster, and it belongs to no Deployment. Pods a listed controller created are
dropped the moment they are parsed: they are that controller's pod template
with a generated name. There is no `log` and no `exec` anywhere in the file.

```sh
kubectl apply -f cluster/readonly-rbac.yaml
```

Two claims in that file are worth verifying rather than believing:

```sh
# what it grants
kubectl auth can-i --list --as=system:serviceaccount:stathe:stathe

# what it does not
kubectl auth can-i get secrets      --as=system:serviceaccount:stathe:stathe   # no
kubectl auth can-i create pods      --as=system:serviceaccount:stathe:stathe   # no
kubectl auth can-i delete deployments --as=system:serviceaccount:stathe:stathe # no
```

There is no `get` and no `watch`, because the code does not call them. Secrets
are absent on purpose: stathe has no permission to read them at all.

ConfigMaps are the one place to be precise. Kubernetes cannot list only the key
names, so the API server returns each ConfigMap in full, values included, and
that response reaches the machine running stathe. The code keeps the key names
and discards the values the moment each object is parsed: they are never
stored, logged, written to a report or sent anywhere. The code that does this
is a few lines in `internal/scan/cluster.go`, short enough for a security
officer to read before approving the run.

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
| `--json` | Emit the assessment as a JSON document (see below) |
| `--framework NAME` | Annotate each finding with the obligation it evidences |
| `--fail-on LEVEL` | Exit 1 when a finding at this severity or above remains |
| `--exceptions DIR` | Where to look for `.stathe.yaml` |
| `--platform-namespaces NS,NS` | Namespaces belonging to whoever runs the platform rather than to the team being assessed, on top of the `kube-*` defaults |

#### `--summary`

One line per check, and under it what the findings have in common — only when
grouping actually reduces the problem:

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

20 findings: 9 high, 7 medium, 4 low
```

For SC-07 that grouping is by image, not by workload: eighteen findings from
three charts are three decisions, and the fix is per image. The summary ends
with the commands that follow it, because a view that deliberately withholds
the detail has to say where the detail is.

#### `--platform-namespaces`

A real cluster runs a GitOps controller, a policy engine and a
runtime-security agent, and those are not the team's findings. stathe only
knows the `kube-*` namespaces by default, so name the rest:

```sh
stathe check --context production --platform-namespaces fleet-system,cattle-system,kyverno,falco
```

Their resources are left out of the checks, counted, and listed under
`NOT ASSESSED` with the reason that you declared them — distinct from the
reason given for the namespaces every cluster has. The set ends up in the JSON
document too, because which namespaces an assessment held out of scope is part
of what it did, and two assessments are only comparable if that is recorded
rather than remembered.

This is a statement about **scope**. A statement about **risk** — a privileged
agent that has to be privileged — belongs in
[`.stathe.yaml`](docs/accepted-risk.md) instead.

### `stathe diff`

The retest. "We fixed it" is a claim; a diff against the assessment that found
it is evidence.

```sh
stathe check --context production --json > 2026-q3.json
# ... the client does the work, a quarter passes ...
stathe check --context production --json > 2026-q4.json

stathe diff 2026-q3.json 2026-q4.json
```

```console
Before   2026-07-02 09:15 CEST  production  stathe v0.3.1  70 resources, 20 findings
After    2026-10-01 09:02 CEST  production  stathe v0.3.1  71 resources, 18 findings

FIXED (2)
  SC-06   high     clusterrolebinding/ci-runner-admin   grants cluster-admin to serviceaccount orders/ci-runner
  SC-07   high     web/deployment/web                   image "nginx:latest" uses a floating tag that can change under you

2 fixed, 0 new, 18 unchanged
```

| Flag | Meaning |
|---|---|
| `--fail-on-new` | Exit 1 when the later assessment has findings the earlier one did not |

Three things it will not do:

- **Count an accepted risk as fixed.** A finding that moved into `.stathe.yaml`
  appears under `ACCEPTED SINCE`, never under `FIXED`. It is the most
  flattering lie this tool could tell, so it is a test rather than an
  intention.
- **Hide that the tool changed.** If the two assessments came from different
  versions of stathe, the diff says so before the counts: a new finding can
  also be a check that did not exist before.
- **Treat an old file as equivalent.** A findings file from before the document
  format records neither its date nor what it was pointed at, and the diff and
  the report cover both say so instead of letting your report date stand in for
  the assessment date.

Findings are matched on ID, resource **and** detail. One deployment can hold
two SC-05 findings, and treating them as one would hide the one that is left
after the other is fixed.

### The JSON document

`check --json` emits one object, not a bare array:

```json
{
  "schema_version": 2,
  "stathe_version": "v0.3.1",
  "assessed_at": "2026-10-30T08:21:59Z",
  "source": "production",
  "resources_checked": 70,
  "findings": [ ... ],
  "accepted": [ ... ],
  "lapsed": [ ... ],
  "not_assessed": [ ... ]
}
```

Everything a reader needs before treating the file as evidence rather than as
output: which version looked at what, when, what was accepted and why, and what
was filtered out before the checks ran.

The findings are in a total order — risk, ID, resource, detail — so two
assessments of an unchanged cluster produce the same document and every line a
diff shows is a line that changed in the cluster. Only `assessed_at` moves
between two identical runs.

Version 1 was that bare array. `report` and `diff` still read it, and both say
on sight that it carries no record of the run behind it.

### `stathe report`

```sh
stathe check --context production --json > findings.json
stathe report --findings findings.json \
  --client "Acme B.V." \
  --environment "production" \
  --framework nis2 \
  --out report.html
```

Produces a document with a cover, a severity summary, one card per finding with
its affected resources, and — with `--framework` — a section grouping findings
by article. The cover records which version of stathe produced it, so two
assessments months apart are comparable.

For a PDF:

```sh
google-chrome --headless=new --no-pdf-header-footer \
  --print-to-pdf=report.pdf report.html
```

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
> digest cannot, and stathe's own `SC-07` check would flag the tag. Find the
> digest on the [package page](https://github.com/stathe-io/stathe/pkgs/container/stathe).

### GitHub Actions

```yaml
- name: Assess the manifests
  run: |
    docker run --rm -v "$PWD:/work:ro" \
      ghcr.io/stathe-io/stathe:v0.3.0 \
      check --manifests /work/k8s --fail-on high
```

### GitLab CI

```yaml
stathe:
  image: ghcr.io/stathe-io/stathe:v0.3.0
  script:
    - stathe check --manifests ./k8s --fail-on high
```

---

## Accepted risk

`.stathe.yaml`, next to the manifests or in the working directory, records what
a team has decided to live with.

```yaml
exceptions:
  - id: SC-09
    resource: "payments/*"       # exact resource, a prefix, or "*"
    reason: "LimitRange on the namespace sets a default memory limit"
    expires: 2027-03-01
```

Worked examples for the cases that actually come up -- a runtime-security
agent, a CNI, a chart that cannot pin a digest -- are in
[docs/accepted-risk.md](docs/accepted-risk.md).

Three rules make this a register rather than a mute button.

**A reason is required.** An entry without one is refused, not honoured. An
undocumented suppression is how a risk stops existing on paper while still
existing in the cluster. Write the sentence you would say to an auditor.

**An expiry is required.** Accepted risk is a decision taken in a context, and
contexts change. Pick a date by which someone will look again.

**Accepted findings are still counted and printed.** A run reporting 17 when it
suppressed 2 is the lie an auditor catches.

```console
18 findings: 9 high, 7 medium, 2 low

2 accepted in .stathe.yaml:
  SC-09   payments/deployment/api    LimitRange sets a default (until 2027-03-01)
  SC-09   payments/deployment/worker LimitRange sets a default (until 2027-03-01)
```

When an expiry passes, the finding comes back carrying the reason it was
accepted and the date that ran out, so a build turning red arrives with an
explanation rather than a mystery.

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
| `SC-06` | Cluster-admin bindings | Any subject bound to `cluster-admin` — service accounts, users, and the aggregate groups such as `system:authenticated` — excluding the control plane's own identities, which are listed under `NOT ASSESSED` | high |
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
stathe report --findings findings.json --client "Acme" --framework nis2 --out report.html
stathe compliance
```

`stathe compliance` prints coverage of NIS2 Article 21(2): six of the ten
measures, **and the four it cannot evidence** — incident handling, assessing
effectiveness, cyber hygiene and training, and multi-factor authentication.
Those are organisational. No cluster scanner can produce evidence for them, and
a coverage number that hides them is worth less than one that does not.

stathe does not certify, attest or determine compliance, and the report says so
on its own face.

---

## The demo cluster

A k3d cluster running "Northwind Logistics", four services across three
namespaces with seven deliberate weaknesses. It exists so the tool can be
tested and demonstrated without borrowing anyone's production.

```sh
make up        # k3d cluster with Traefik, plus the demo app
make findings  # what stathe makes of it
make down      # remove it
```

**Do not apply these manifests to a cluster you care about.**

[`cluster/attack.md`](cluster/attack.md) walks through proving the weaknesses
by hand: reach the database from the web pod, read the password out of a
ConfigMap, escape the privileged container. Then apply the baseline and watch
each one close.

---

## Development

```sh
make test              # go test ./...
make validate          # assess the demo manifests without a cluster
go vet ./...
```

The tests are the interesting part of this repository. Several of them exist
because a check once passed for the wrong reason:

- `TestNorthwindFindings` matches on the detail text rather than the finding
  ID, because an earlier version stayed green when a privileged container was
  set to `privileged: false`.
- `TestWarnHalfNeverEnforces` rejects a Pod Security `enforce` label anywhere
  in `warn/`, including inside a YAML comment. It caught one.
- `TestNIS2RefsAreReal` rejects any citation that is not a real measure in
  Article 21(2), so a typo cannot reach a client report.
- `TestExpiredExceptionStopsSuppressing` pins that a lapsed acceptance puts the
  finding back and says which acceptance ran out.

A check is finished when it has been watched failing for the right reason, not
when it passes.

---

## Layout

| Directory | Contents |
|---|---|
| `cmd/stathe/` | The CLI |
| `internal/scan/` | Checks, the finding catalogue, the regulatory mapping, exceptions |
| `internal/report/` | Report generation and its template |
| `internal/baseline/` | The generated fix |
| `cluster/` | The demo cluster, the RBAC manifest, the walkthrough |

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

Built by [Jarno Kristelijn](https://www.linkedin.com/in/jarnokristelijn/),
DevSecOps engineer in the Netherlands. A finding it gets wrong is worth more to
me than one it gets right — [open an issue](https://github.com/stathe-io/stathe/issues).
