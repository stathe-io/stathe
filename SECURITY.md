# Security

stathe is a tool people point at other people's clusters, so it is held to the
standard it asks of them.

## Reporting a vulnerability

Please report it privately through GitHub: **Security → Report a vulnerability**
on this repository. Do not open a public issue for something exploitable.

What to expect: an acknowledgement within five working days, a fix or a
mitigation plan as soon as the issue is understood, and credit in the release
notes if you want it. A finding stathe gets wrong is a bug; a finding stathe
could be made to *cause* is a vulnerability. Both are welcome.

## What stathe reads, writes and trusts

| | |
|---|---|
| **Reads** | `list` on the resource types in [`cluster/readonly-rbac.yaml`](cluster/readonly-rbac.yaml). Never Secrets. |
| **One POST** | `preflight` sends a `SelfSubjectAccessReview`: a question to the API server about what the account may do. It persists nothing and changes nothing, and by default every authenticated identity may ask it, so the role does not grant it. It does appear in the API audit log as a `create`. |
| **Holds in memory** | ConfigMap values arrive in the API response and are discarded as each object is parsed. They are never stored, logged or reported. |
| **Writes** | Only what you point it at: `--out` for reports, `--out` for the baseline. Nothing in the cluster, ever. |
| **Network** | Talks to the Kubernetes API server of the context you chose. No telemetry, no update check, nothing else. |
| **Trusts** | Your kubeconfig (see the threat model: an `exec` credential plugin in a kubeconfig runs a command). Manifests are treated as untrusted input. |

The reasoning behind each line is in [`docs/threat-model.md`](docs/threat-model.md).

## Verify what you run

Releases are built from a tag by [`release.yml`](.github/workflows/release.yml)
and by nothing else. They are signed without a long-lived key, so there is no
private key to steal; the signature proves *which workflow in which repository*
produced the artifact.

Container image:

```sh
cosign verify ghcr.io/stathe-io/stathe:v0.3.0 \
  --certificate-identity-regexp '^https://github.com/stathe-io/stathe/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/stathe-io/stathe:v0.3.0 --repo stathe-io/stathe
```

Binaries (download `SHA256SUMS` and `SHA256SUMS.bundle` from the release):

```sh
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.bundle \
  --certificate-identity-regexp '^https://github.com/stathe-io/stathe/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --check --ignore-missing SHA256SUMS
```

Pin the image by digest in anything you care about. The image also carries an
SBOM and SLSA provenance as OCI attestations.

For an air-gapped host, `make image-save` writes a tar you can carry across;
verify the digest against the signed release before you load it.

## Known limits

- stathe assesses configuration, not running behaviour and not images. A clean
  report is not a statement that a cluster is secure, and the report says so.
- Findings describe what the configuration *allows*, not what is exploitable.
- The base images are referenced by tag in the Dockerfile and are not yet
  pinned by digest. This is tracked as a TODO in the Dockerfile.
