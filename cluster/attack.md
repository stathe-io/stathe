# Attacking Northwind

Northwind carries deliberate weaknesses. This walkthrough shows you how to
demonstrate each one yourself, so that the baseline that follows fixes
something you have actually seen rather than something you were told about.

Everything here runs against your own local k3d cluster. Do not point any of it
at a cluster you do not own.

```sh
make up
```

Every command below was run against that cluster, and the output is what it
actually printed.

---

## NW-01 · Every pod can reach every other pod

The web front end is the one component exposed to the internet. The customer
database lives in a different namespace, which feels like separation. It is not.

```sh
kubectl -n northwind-web exec deploy/web -- \
  bash -c 'cat < /dev/null > /dev/tcp/postgres.northwind-orders.svc.cluster.local/5432 && echo OPEN'
```

```text
OPEN
```

The connection succeeds. There is no namespace boundary for network traffic in
Kubernetes unless you create one — namespaces separate names, not packets.

**Why it matters.** One compromised front end is a direct path to customer data.
Separation would not prevent the break-in, but it would contain it.

**What the baseline does.** A default-deny NetworkPolicy per namespace, with
explicit exceptions for DNS and the ingress controller. After that, this same
command times out while the application keeps working.

---

## NW-04 · The database password is readable by anyone

It sits in a ConfigMap, which is not a secret and is rarely access-controlled.

```sh
kubectl -n northwind-orders get cm orders-config -o jsonpath='{.data.DB_PASSWORD}'
```

```text
hunter2-demo-only
```

No decoding needed. Anyone with read access to the namespace has it, and so
does anyone with read access to the Git repository it was committed from —
including CI runners, backups, and the contractor who left last year.

**Why it matters.** Credentials in configuration spread silently. Rotating one
means finding every copy first.

**What the baseline does.** Flags it, and points at Sealed Secrets or an
external secret store. Moving the value is a change only your team can make.

---

## NW-05 · A privileged container is root on the node

The tracking service runs privileged and mounts the host filesystem.

```sh
kubectl -n northwind-tracking exec deploy/tracking -- ls /host
```

```text
bin dev etc k3d lib proc run sbin sys tmp usr var
```

That is not the container's filesystem. That is the node's. From here an
attacker can read every secret mounted on that node, write to systemd, or
install anything that survives a pod restart.

**Why it matters.** Container isolation is the thing standing between a
compromised application and the machine it runs on. `privileged: true` turns
nearly all of it off at once.

**What the baseline does.** Pod Security Admission in warn and audit mode
reports it immediately. Moving to enforce is a later, deliberate step.

---

## NW-06 · A service account that owns the cluster

```sh
kubectl auth can-i --list --as=system:serviceaccount:northwind-tracking:tracking
```

```text
Resources    Non-Resource URLs   Resource Names   Verbs
*.*          []                  []               [*]
```

Every resource, every verb. That token is mounted into the tracking pod, so
whoever reaches that pod — through the application, through a dependency,
through the privileged container above — controls the entire cluster.

Nobody grants this on purpose. A CI runner needed "just enough" rights once,
and nobody narrowed them down afterwards.

**Why it matters.** It converts a single application compromise into a full
cluster compromise, with no further effort required.

**What the baseline does.** Lists every cluster-admin binding so you can work
through them. The fix per account is to check what it actually uses
(`kubectl auth can-i --list --as=...`), write a Role for exactly that, and
remove the binding.

---

## NW-07 · You cannot prove what is running

```sh
kubectl -n northwind-web get deploy web -o jsonpath='{.spec.template.spec.containers[0].image}'
```

```text
nginx:latest
```

Which version is that? Nobody knows, and after the next node restart it may be
a different one.

**Why it matters.** During an incident you cannot say what was running. A
rollback is not really a rollback. A scanner that called the image clean was
talking about a different image than the one running now.

**What the baseline does.** Reports mutable tags and images without a digest.
Pinning them is a change in your manifests, with Renovate proposing updates.

---

## NW-03 and NW-09 · The quiet ones

Two base images are past end of life:

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' | sort -u
```

Node 16 and Python 3.8 both stopped receiving fixes years ago. Every CVE found
from now on stays in them permanently.

No container has a memory limit either, so a single runaway process can take
down everything else on the node. That is usually filed as an availability
problem rather than a security one, right up until someone uses it on purpose.

---

## Seeing all of it at once

```sh
make validate
```

```text
20 findings: 9 high, 7 medium, 4 low

Nothing was changed. This command only reads.
```

That is `stathe check` reading the manifests. The point of the exercise is
what comes next: apply the baseline, run it again, and watch the count fall
without a single workload going down.
