# Using stathe

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

## Getting started

### 1. Approve the access

Hand [`cluster/readonly-rbac.yaml`](../cluster/readonly-rbac.yaml) to whoever owns
the cluster before anything runs. It is the whole permission set — eleven resource
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
| `--json` | Emit the assessment as a [JSON document](evidence.md) |
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
[`.stathe.yaml`](accepted-risk.md).

### `stathe diff`

The retest. "We fixed it" is a claim; a diff against the assessment that found
it is evidence — and it never counts a risk that moved into `.stathe.yaml` as a
fix. [evidence.md](evidence.md) has the output, `--fail-on-new`, and
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
> docker buildx imagetools inspect ghcr.io/stathe-io/stathe:v0.3.2 | grep '^Digest:'
> ```

### GitHub Actions

```yaml
- name: Assess the manifests
  run: |
    docker run --rm -v "$PWD:/work:ro" \
      ghcr.io/stathe-io/stathe:v0.3.2 \
      check --manifests /work/k8s --fail-on high
```

### GitLab CI

```yaml
stathe:
  image: ghcr.io/stathe-io/stathe:v0.3.2
  script:
    - stathe check --manifests ./k8s --fail-on high
```


## Accepted risk

Some findings are true and are going to stay: a runtime-security agent has to
mount the host filesystem. `.stathe.yaml` records that decision — the finding
stays in the report, under its own heading, with a reason and an expiry date,
and comes back by itself when the date passes. An entry without both is
refused.

[accepted-risk.md](accepted-risk.md) has the file format and the
cases that actually come up.


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

[`cluster/attack.md`](../cluster/attack.md) proves each weakness by hand — reach
the database from the web pod, read the password out of a ConfigMap, escape the
privileged container — then applies the baseline and closes them.

Working on stathe itself: [development.md](development.md).
