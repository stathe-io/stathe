# k8s-security-baseline

A practical security baseline for Kubernetes clusters, plus a deliberately insecure
demo cluster to practise on.

Most clusters run on defaults: every workload can reach every other workload,
containers have more rights than they need, and nobody can say exactly which
software is running or where it came from. This repository collects the
policies, network rules and scanning setup that fix that — in report-only mode
first, so nothing breaks while you find out where you stand.

> **Status: early.** The demo cluster is being built first. Nothing here is
> stable yet. Issues and pull requests are welcome.

## What this will contain

| Directory | Contents |
|---|---|
| `cluster/` | A k3d cluster with "Northwind", a demo app with ten deliberate weaknesses |
| `baseline/` | The baseline as Kustomize: Pod Security Admission, NetworkPolicies, Kyverno policies, Trivy Operator |
| `insight/` | Read-only assessment scripts — what is running, and what is wrong with it |
| `report/` | Turns the raw scan output into a readable report |

## Getting started

```
git clone https://github.com/TestRebel/k8s-security-baseline
cd k8s-security-baseline
make up
```

This brings up a local k3d cluster with the Northwind demo app. It should take
under ten minutes on a clean laptop. `make down` removes everything again.

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
