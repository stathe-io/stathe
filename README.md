# stathe

Find out how exposed your Kubernetes cluster is, without changing anything.

> **Nothing here runs yet.** This repository is being built in the open and
> currently holds the plan, not the tool. The demo cluster comes first, then
> `stathe check`. Watch the repo if you want to know when that changes.

Most clusters run on defaults: every workload can reach every other workload,
containers hold more rights than they need, and nobody can say exactly which
software is running or where it came from. `stathe check` will tell you which
of those apply to you, read-only and without an account. The rest of this
repository is what you do about it.

## Planned commands

| Command | What it will do |
|---|---|
| `stathe check` | Read-only assessment of a cluster and its pipelines |
| `stathe report` | Turns the findings into a readable report |
| `stathe baseline` | Generates the baseline as a merge request for your own repo |
| `stathe preflight` | Verifies access before a cluster is assessed |

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
