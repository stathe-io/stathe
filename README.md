# stathe

Find out how exposed your Kubernetes cluster is, without changing anything.

> **Private beta.** `check`, `report` and `compliance` work today against a
> live cluster or a directory of manifests. `baseline` and `preflight` are not
> written yet. There is no published image or release, so build from source.

Most clusters run on defaults: every workload can reach every other workload,
containers hold more rights than they need, and nobody can say exactly which
software is running or where it came from. `stathe check` tells you which of
those apply to you, read-only and without an account. The rest of this
repository is what you do about it.

## Commands

| Command | Status | What it does |
|---|---|---|
| `stathe check` | works | Read-only assessment of a cluster or of manifests on disk |
| `stathe report` | works | Turns the findings into a client-ready document |
| `stathe compliance` | works | Which NIS2 measures these checks can and cannot evidence |
| `stathe baseline` | not built | Generates the baseline as a merge request for your own repo |
| `stathe preflight` | not built | Verifies access before a cluster is assessed |

```sh
go run ./cmd/stathe check --manifests cluster/northwind
go run ./cmd/stathe check --context my-cluster --framework nis2
go run ./cmd/stathe compliance
```

## Permissions

`stathe` only ever lists. [`cluster/readonly-rbac.yaml`](cluster/readonly-rbac.yaml)
is the whole permission set — six resource types, one verb, no access to
Secrets — and it is meant to be read and approved before anything runs. The
findings are identical whether stathe runs as that ServiceAccount or as
cluster-admin.

## Regulatory mapping

Every finding carries the obligation it is evidence about, under NIS2
(Article 21(2)), DORA and ISO/IEC 27001:2022 Annex A. `stathe compliance`
prints the coverage, including the four NIS2 measures that are organisational
and that no cluster scanner can evidence.

stathe does not certify, attest or determine compliance, and the report says
so on its own face.

## Layout

| Directory | Contents |
|---|---|
| `cluster/` | A k3d cluster with "Northwind", a demo app carrying ten deliberate weaknesses |
| `baseline/` | The baseline as Kustomize: Pod Security Admission, NetworkPolicies, Kyverno policies, Trivy Operator |
| `insight/` | The checks behind `stathe check` |
| `report/` | Report generation |

## The demo cluster

Rather than asking anyone to point an unfamiliar tool at their own cluster, the
first thing being built here is one that exists to be broken: a local k3d
cluster running Northwind, a small logistics app carrying ten deliberate
weaknesses. `make up` will bring it up in under ten minutes on a clean laptop
and `make down` will remove all of it.

See [`cluster/attack.md`](cluster/attack.md) for the walkthrough: how to
demonstrate each weakness yourself, before you apply the baseline and watch the
findings disappear.

## Principles

**Nothing breaks.** Every guardrail starts in audit or warn mode. You get a list
and a conversation, not a blocked deployment and an angry developer.

**Look, warn, then block.** In that order, every time. Going straight to enforce
is how you lose the room.

**As code, or it does not exist.** Everything is a manifest in Git, reviewable
and revertible. A rollback is `git revert`.

## Requirements

- Docker
- [k3d](https://k3d.io)
- kubectl
- make

## Licence

Apache 2.0. Commercial use is fine.
