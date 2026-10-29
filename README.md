# stathe

**See how far an attacker gets.** A read-only Kubernetes assessment: six checks
on the configuration that decides blast radius, a report you can hand to an
auditor, and the policies that close the findings.

> **Private beta.** `preflight`, `check`, `report`, `baseline` and `compliance`
> work today. There is no published image or release yet, so build from source.
> The commands below assume `stathe` is on your `PATH`; use
> `go run ./cmd/stathe` while you are in this repository.

```console
$ stathe check --context production --summary
Assessed 70 resources in production

SC-01   high      3  No network separation between workloads
SC-04   high      1  Credentials stored in plain configuration
SC-05   high      5  Container runs with excessive privileges
SC-06   high      2  Service account bound to cluster-admin
SC-07   high      4  Workload uses a mutable image tag
SC-09   low       4  Workload has no resource limits

19 findings: 9 high, 6 medium, 4 low

Nothing was changed. This command only reads.
```

---

## Why six checks

kubescape runs hundreds. Trivy finds every CVE in your images. Both are good,
and stathe does not try to beat them at it.

These six decide how far an attacker gets once they are inside, and that is a
question about configuration rather than about a CVE count. A fully patched
image, in a flat network, with a service account bound to `cluster-admin`, is
still one bad afternoon.

A scan that returns everything returns nothing actionable. Someone still has to
decide which twenty of the four hundred matter. stathe ships that decision
instead of the raw list: the platform's own namespaces and the distribution's
own bindings are filtered out before you see anything.

---

## Install

### From source

```sh
git clone https://github.com/stathe-io/stathe
cd stathe
go build -ldflags "-X main.version=$(git describe --tags --always)" -o stathe ./cmd/stathe
```

Go 1.24 or newer. There are no runtime dependencies: the result is a single
static binary.

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
  -v $HOME/.kube:/kube:ro -e KUBECONFIG=/kube/config \
  stathe:v0.3.0 check
```

---

## Getting started

### 1. Approve the access

Hand [`cluster/readonly-rbac.yaml`](cluster/readonly-rbac.yaml) to whoever owns
the cluster before anything runs. It is the whole permission set: six resource
types, one verb.

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
are absent on purpose: stathe reads ConfigMap *key names* to spot credentials
stored in the clear, and never reads a value of any kind.

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
| `stathe report` | Turns findings into a document, with an optional regulatory mapping |
| `stathe baseline` | Writes the configuration that closes the findings, and applies none of it |
| `stathe compliance` | Which NIS2 measures these checks evidence, and the four they cannot |

### `stathe check`

| Flag | Meaning |
|---|---|
| `--context NAME` | Assess a live cluster. Omit to use the current kubectl context |
| `--manifests DIR` | Assess files on disk, with no cluster at all |
| `--summary` | One line per check instead of one per finding |
| `--json` | Emit findings as JSON |
| `--framework NAME` | Annotate each finding with the obligation it evidences |
| `--fail-on LEVEL` | Exit 1 when a finding at this severity or above remains |
| `--exceptions DIR` | Where to look for `.stathe.yaml` |

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

### GitHub Actions

```yaml
- name: Assess the manifests
  run: |
    docker run --rm -v "$PWD:/work:ro" \
      ghcr.io/stathe-io/stathe:0.3.0 \
      check --manifests /work/k8s --fail-on high
```

### GitLab CI

```yaml
stathe:
  image: ghcr.io/stathe-io/stathe:0.3.0
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
| `SC-04` | Plaintext credentials | ConfigMap keys holding passwords, tokens or connection strings | high |
| `SC-05` | Workload privilege | Privileged containers, host filesystem mounts, missing `securityContext` | high / medium |
| `SC-06` | Cluster-admin bindings | ServiceAccounts bound to `cluster-admin`, excluding the platform's own | high |
| `SC-07` | Image provenance | Floating tags like `:latest` (high), and tags that are not digests (medium) | high / medium |
| `SC-09` | Resource limits | Containers with no memory limit, where one workload starves a node | low |

Severity is the severity for a production platform, not a generic score. Every
finding carries why it matters and the next step.

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
