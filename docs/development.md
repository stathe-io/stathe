# Development

Working on stathe itself.

## Building and testing

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

