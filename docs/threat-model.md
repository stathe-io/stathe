# Threat model

A security tool that has not been threat-modelled is asking a client to take its
safety on trust. This is the model, kept short enough to read before approving
a run. It lists what is defended, what is not, and where each defence lives.

## What stathe is, for this purpose

A single static binary run by a consultant, on a laptop, in a pipeline or from a
container, against one of two inputs: a **live cluster** through a kubeconfig,
or a **directory of manifests**. It produces findings, an HTML report and, for
`baseline`, a directory of YAML. It has no server, no daemon and no state.

## What is worth protecting

1. **The client's cluster** must not be changed by an assessment.
2. **The client's data** (resource names, namespaces, topology, and any
   ConfigMap value that passes through memory) must not leak.
3. **The consultant's machine** must not be compromised by what stathe reads.
4. **The integrity of the result**: a report must say what the cluster says, and
   a release must be what the source says.

## Trust boundaries and what crosses them

| Input | Trust | Why it matters |
|---|---|---|
| Manifests (`--manifests`) | **Untrusted.** In a pipeline they come from a pull request. | Hostile names, odd types, huge or recursive YAML. |
| Cluster API responses | Mostly trusted, **not fully.** A compromised cluster controls labels, annotations and ConfigMap keys. | Content ends up in the HTML report. |
| Kubeconfig | **Trusted by definition.** | An `exec` credential plugin runs a command. Use only a kubeconfig you would run a script from. |
| Command-line flags | Trusted (the operator). | |
| Dependencies and base images | Trusted only as far as they are verified. | The k8s client library brings a large dependency tree. |
| Release artifacts | Verified by signature and provenance. | See `SECURITY.md`. |

## Threats and defences

| Threat | Defence | Status |
|---|---|---|
| An assessment modifies the cluster | RBAC grants only `list`; `check` and `baseline` never call a write verb; the permission set is a reviewable file. The one exception is `preflight`, which POSTs a `SelfSubjectAccessReview`: stateless, persists nothing, askable by default by every authenticated identity, and visible in the audit log as a `create`. | In place; say so to the client up front |
| A hostile manifest writes a file outside `--out` (path traversal via a namespace name) | Namespaces must be valid DNS labels before they become file names; the write path is checked to stay inside `--out`. | **Fixed in this change**, with a regression test. Found while writing this document. |
| A hostile name injects YAML into generated baseline files | Same namespace check; generated files only contain validated names. | **Fixed in this change** |
| A hostile ConfigMap key, label or name injects script into the report | The report uses `html/template`, which escapes by context. | In place; add a test that a `<script>` name is rendered inert |
| A malformed manifest crashes or hangs the loader | The loader returns errors rather than skipping; `FuzzLoadDir` runs the loader and every check over arbitrary input. | Fuzz target added; **not yet run for long** |
| ConfigMap values leak | Values are dropped at parse time; never stored, logged or reported. | In place; stated honestly in `readonly-rbac.yaml` and the README |
| Secret values leak | The role has no access to Secrets. | In place |
| A malicious kubeconfig runs code | Cannot be defended from inside the tool. Documented. The container image has no shell and no credential plugins. | Documented |
| A compromised dependency | `go mod verify` in CI and in the image build; `govulncheck` in CI; Dependabot. | Added in this change |
| A tampered release or image | Keyless signature, SLSA provenance and SBOM; no long-lived signing key. | Added in this change (workflow not yet run) |
| A tag moved under a pipeline | Image published by tag *and* digest; documentation tells users to pin by digest; no `latest`. | Partially: base images are still pinned by tag |
| A report is mistaken for a compliance certificate | The report states on its face that stathe does not certify. | In place |

## Not defended

- A client who runs stathe with credentials broader than the role it ships.
  `preflight` reports what the account can do, but cannot reduce it.
- Side channels on the consultant's machine (swap, core dumps) while ConfigMap
  values are briefly in memory.
- Anything an attacker can do with a report once it exists. Reports name real
  resources; treat them as confidential client material.

## Open items, in order

1. Run the fuzz target for hours, not seconds, and fix what it finds.
2. Pin base images by digest.
3. Pin workflow actions by commit SHA.
4. Update the Kubernetes client libraries (`go.mod` is on `v0.31`) and clear
   whatever `govulncheck` reports.
5. Add a report test with a hostile resource name.
6. Enable private vulnerability reporting on the repository.
