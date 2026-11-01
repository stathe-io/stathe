<!-- <p align="center">
  <img src="docs/banner.png" alt="stathe" width="760">
</p> -->

<p align="center">
  An audit-ready Kubernetes assessment you can hand to a regulator.
  Read-only, one command, nothing installed in the cluster.
</p>

<p align="center">
  <a href="docs/install.md">Install</a> &middot;
  <a href="docs/usage.md">Usage</a> &middot;
  <a href="docs/checks.md">Checks</a> &middot;
  <a href="cluster/readonly-rbac.yaml">Permissions</a>
</p>

Six checks, against a live cluster or a directory of manifests. Clone this
repository and the output below is the output you get — `cluster/northwind` is
a deliberately broken demo cluster that ships with it:

```console
$ stathe check --manifests cluster/northwind --summary
Assessed 17 resources in cluster/northwind

SC-01   high      3  No network separation between workloads
SC-04   high      2  Credentials stored in plain configuration
SC-05   high      6  Container runs with excessive privileges
                  3× northwind-tracking/deployment/tracking
                  1× northwind-orders/deployment/orders
                  1× northwind-orders/deployment/postgres
                     and 1 more
SC-06   high      2  Cluster-admin granted outside the platform's own bindings
SC-07   high      4  Workload uses a mutable image tag
SC-09   low       4  Workload has no resource limits

21 findings: 10 high, 7 medium, 4 low
```

Kubescape runs hundreds of checks. Trivy finds every CVE in your images. Both
are good, free, and broader than this. stathe is for the part they leave to
you: turning a scan into an assessment somebody else will accept as evidence.

- **Permissions a client approves in advance.** Eleven resource types, one verb,
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

## Documentation

- [Install](docs/install.md): binary, container, verifying a release
- [Usage](docs/usage.md): approving access, `preflight`, `check`, `diff`, `report`, `baseline`, pipelines, the demo cluster
- [Checks](docs/checks.md): what each check catches, what is not covered, the regulatory mapping
- [Evidence](docs/evidence.md): the JSON document and `stathe diff`
- [Accepted risk](docs/accepted-risk.md): `.stathe.yaml`
- [Security](SECURITY.md) and the [threat model](docs/threat-model.md)
- [Development](docs/development.md)

## Licence

Apache 2.0. See [LICENSE](LICENSE).

A finding it gets wrong is worth more than one it gets right —
[open an issue](https://github.com/stathe-io/stathe/issues).
