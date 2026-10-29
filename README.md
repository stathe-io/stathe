# stathe

Find out how exposed your Kubernetes cluster is, without changing anything.

```sh
docker run --rm -v ~/.kube:/root/.kube:ro ghcr.io/stathe-io/stathe check
```

No account, no signup, no key. It reads, it reports, it changes nothing.

Most clusters run on defaults: every workload can reach every other workload,
containers hold more rights than they need, and nobody can say exactly which
software is running or where it came from. `stathe check` tells you which of
those apply to you. The rest of this repository is what you do about it.

> **Status: early.** The demo cluster is being built first, then `check`.
> Nothing here is stable yet. Issues and pull requests are welcome.

## Commands

| Command | What it does |
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

## Try it against the demo cluster

If you would rather not point an unfamiliar tool at your own cluster, start with
one built to be broken:

```sh
git clone https://github.com/TestRebel/k8s-security-baseline
cd k8s-security-baseline
make up
```

This brings up a local k3d cluster running Northwind. It should take under ten
minutes on a clean laptop, and `make down` removes all of it.

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
