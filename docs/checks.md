# Checks

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
decision is yours, and [`.stathe.yaml`](accepted-risk.md) is where it goes.

## The checks

IDs are `SC-nn`, for stathe check. They are stable: an ID never changes meaning
and is never reused, because a previous report, a `.stathe.yaml` and a ticket
title all refer to it. The numbering has gaps where checks are planned but not
written.

| ID | Check | What it catches | Severity |
|---|---|---|---|
| `SC-01` | Network separation | Namespaces with no NetworkPolicy, where any pod reaches any other pod | high |
| `SC-04` | Plaintext credentials | ConfigMap keys and literal container `env` values whose name *ends* in a credential word (`DB_PASSWORD`, `client-secret`, `STRIPE_API_KEY`), never ones that merely contain it (`SECRET_SCANNER_ENABLED` is a feature flag), and never a variable taken from a Secret | high |
| `SC-05` | Workload privilege | Privileged or root containers and init containers, missing `securityContext`, and host mounts ranked by what they are worth: a container runtime socket or the kubelet's credentials are control of the node, `/proc` is not | high / medium |
| `SC-06` | Cluster-admin bindings | Any subject granted full control — service accounts, users, and aggregate groups such as `system:authenticated` — whether through `cluster-admin` itself or a ClusterRole that wildcards every verb, resource and API group under another name. The control plane's own identities are excluded and listed under `NOT ASSESSED` | high |
| `SC-07` | Image provenance | Floating tags like `:latest` (high), and tags that are not digests (medium), in containers and init containers | high / medium |
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
