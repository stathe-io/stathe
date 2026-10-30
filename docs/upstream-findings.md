# What stathe finds in the tools everyone runs

Ten widely deployed projects, assessed from their own published install
manifests. No cluster involved: `stathe check --manifests` reads files.

This exists for two reasons. It is how stathe gets tested against YAML nobody
on this project wrote — Northwind is a demo whose author also wrote the
checks, so it only ever confirms his own assumptions. And it is a map of where
to look once you know what a cluster runs.

Measured 30 October 2026, with the versions below.

| Tool | Version | What it is | Resources | Findings | Checks |
|---|---|---|---|---|---|
| Argo CD | v3.5.6 | GitOps | 59 | 1 high, 7 medium, 7 low | SC-06, SC-07, SC-09 |
| Kyverno | v1.19.2 | policy engine | 70 | 1 high, 4 medium | SC-01, SC-07 |
| cert-manager | v1.16.2 | certificates | 49 | 1 high, 3 medium, 3 low | SC-01, SC-07, SC-09 |
| ingress-nginx | v1.11.3 | ingress | 19 | 1 high, 3 low | SC-01, SC-09 |
| MetalLB | v0.14.8 | load balancer | 24 | 1 high, 2 medium, 2 low | SC-01, SC-07, SC-09 |
| Calico | v3.33.0 | CNI | 38 | 2 high, 3 medium, 2 low | SC-01, SC-05, SC-07, SC-09 |
| Longhorn | v1.13.0 | storage | 62 | 3 high, 9 medium, 5 low | SC-05, SC-06, SC-07, SC-09 |
| Rook-Ceph | v1.21.1 | storage | 7 | 1 high, 1 medium, 1 low | SC-01, SC-07, SC-09 |
| Online Boutique | v0.10.7 | demo application | 35 | 12 medium | SC-07 |

Cilium is absent: its `quick-install.yaml` was withdrawn and the project
installs by Helm chart only, which this method does not cover.

## Read this before you quote it

Most of what is in that table is not a mistake by the supplier.

An install manifest ships version tags rather than digests, carries no
NetworkPolicies, and sets no memory limits — because the supplier does not know
your cluster's sizing, your network layout, or your policy. Those decisions
belong to whoever runs it. **SC-07, SC-09 and SC-01 here are addressed to the
operator, not to the project.**

Taking this table to a client as "your tools are insecure" loses the
conversation, and deservedly. It is a list of what to configure, not a list of
what is broken.

## The two worth a conversation

**Argo CD grants one identity everything.** The ClusterRole
`argocd-application-controller` wildcards every verb, resource and API group.
That is documented and necessary — a GitOps controller has to be able to manage
any resource type it is handed. But it means every cluster running Argo CD has
a service account with full control, and whoever can create an Application can
reach it.

**Longhorn binds a service account to `cluster-admin` itself.** Not a wildcard
role under another name: `longhorn-support-bundle` is bound to `cluster-admin`
directly. It is part of the support-bundle feature, installed by default, and
in most clusters never used.

Both are questions you can ask on day one, and both show you know the platform
rather than the scanner.

## What this caught in stathe

Two defects, each found because real manifests do things a demo does not.

**SC-06 matched the name, not the permission.** It looked for
`roleRef.name == "cluster-admin"` and so could not see Argo CD's wildcard
ClusterRole at all. In a cluster that gets reviewed, the wildcard role *is* the
normal form — nobody leaves a literal `cluster-admin` binding lying around.

**A broader host mount ranked lower than a narrower one.** `rankHostPath` only
compared downwards, so `/etc/kubernetes` counted as control of the node while
plain `/etc`, which contains it, fell through to "some other host mount".
Longhorn mounts `/etc`, and the finding read `mounts /dev` — the least alarming
of its five host paths — while `/etc` carried the kubelet's credentials and the
host's SSH keys.

Neither was visible against `cluster/northwind`.

## Reproducing it

```sh
mkdir -p /tmp/upstream && cd /tmp/upstream

curl -sSLO https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/v0.10.7/release/kubernetes-manifests.yaml
curl -sSL -o kyverno.yaml       https://github.com/kyverno/kyverno/releases/download/v1.19.2/install.yaml
curl -sSL -o argocd.yaml        https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.6/manifests/install.yaml
curl -sSL -o cert-manager.yaml  https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml
curl -sSL -o ingress-nginx.yaml https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.3/deploy/static/provider/cloud/deploy.yaml
curl -sSL -o metallb.yaml       https://raw.githubusercontent.com/metallb/metallb/v0.14.8/config/manifests/metallb-native.yaml
curl -sSL -o calico.yaml        https://raw.githubusercontent.com/projectcalico/calico/v3.33.0/manifests/calico.yaml
curl -sSL -o longhorn.yaml      https://raw.githubusercontent.com/longhorn/longhorn/v1.13.0/deploy/longhorn.yaml
curl -sSL -o rook.yaml          https://raw.githubusercontent.com/rook/rook/v1.21.1/deploy/examples/operator.yaml

stathe check --manifests . --summary
```

Pin the versions. Re-running against whatever is current today gives numbers
that cannot be compared with the ones above, which is the same argument SC-07
makes about image tags.

For one project at a time, put its file in a directory of its own — the table
above was built that way, because a finding is only useful here if you know
which project it came from.

## Adding to this

A manifest is worth adding when it exercises something the others do not, not
when it adds another row. The gaps as of this writing:

- **Helm-only projects.** Falco, Cilium and the Prometheus stack publish no
  single manifest. `helm template` produces one, and that output is a different
  dialect of YAML than a hand-written manifest — which is worth testing.
- **Operators that create workloads at runtime.** Rook's operator manifest is
  seven resources; the privileged OSD pods it later creates are not in any
  file. Those only appear against a live cluster.
- **Anything with a mutating webhook**, where what you apply is not what runs.
