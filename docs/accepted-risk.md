# Accepting a risk

Some findings are true and are going to stay. A runtime-security agent has to
mount the host filesystem; that is what it is for. A CNI plugin runs
privileged. A node-exporter DaemonSet reads `/proc` off the node.

stathe has one answer for that, and it is not a flag that hides the finding.
`.stathe.yaml` is the accepted-risk register: the finding stays in the
assessment, moves to its own section with the reason and a date, and comes back
by itself when the date passes.

## The file

Put it next to the manifests, or in the working directory when assessing a live
cluster. Point somewhere else with `--exceptions DIR`.

```yaml
# .stathe.yaml -- accepted risks for the production cluster.
#
# Each entry needs a reason a reader who was not in the room can follow, and a
# date. stathe reports these separately from the findings; it never drops them.
exceptions:
  - id: SC-05
    resource: falco/daemonset/falco
    reason: >
      Runtime security agent. Needs hostPath and privileged to read syscalls
      off the node; this is the documented deployment and the vendor supports
      no other mode. Reviewed with the platform team, risk accepted by the
      CISO on 2026-10-14 (ticket SEC-2291).
    expires: 2027-04-01

  - id: SC-05
    resource: kube-system/daemonset/cilium
    reason: >
      CNI. Privileged by design; removing it removes cluster networking.
      Revisit when Cilium's non-privileged mode leaves beta.
    expires: 2027-04-01

  - id: SC-07
    resource: monitoring/deployment/grafana
    reason: >
      Pinned to a tag rather than a digest because the Helm chart does not
      expose a digest field. ValidatingAdmissionPolicy require-digests already
      rejects anything outside the approved registry, so the exposure is the
      mutable tag inside that registry only. Chart upgrade tracked in PLAT-884.
    expires: 2027-01-15
```

## What stathe does with it

```console
19 findings: 9 high, 6 medium, 4 low

3 accepted in .stathe.yaml:
  SC-05   falco/daemonset/falco       Runtime security agent... (until 2027-04-01)
  SC-05   kube-system/daemonset/cilium  CNI. Privileged by design... (until 2027-04-01)
  SC-07   monitoring/deployment/grafana  Pinned to a tag rather than... (until 2027-01-15)
```

The counts and the accepted list are both printed, always. In the JSON
document the accepted findings are a section of their own, with the reason and
the expiry date, so the report and a pipeline see the same thing.

When a date passes, the acceptance stops suppressing:

```console
The acceptance of SC-07 on monitoring/deployment/grafana expired on 2027-01-15
and no longer applies.
  It was accepted because: Pinned to a tag rather than a digest because...
  Renew the date after deciding again, or fix the finding.
```

The finding is back in the list. That is the point of the date: an accepted
risk that nobody looks at again is an accepted risk that has quietly become a
decision nobody made.

## Rules the format enforces

- **A reason is required.** An entry without one is an error, not a warning.
- **A date is required**, in `YYYY-MM-DD`. There is no "forever".
- **A malformed entry fails the run.** A typo in an exception would otherwise
  silently suppress nothing while looking as though it suppressed something, or
  the reverse, and both are worse than a loud failure.

## When not to use it

- **To quiet a report before a client meeting.** It is in the output either
  way, and an auditor reads the accepted section first.
- **For a whole platform's worth of findings.** If a GitOps controller, a
  policy engine and a security agent are all producing noise, those namespaces
  are not in scope for this assessment: pass
  `--platform-namespaces fleet-system,kyverno,falco` instead. Their resources
  are then left out, counted, and listed under `NOT ASSESSED` — which is a
  statement about scope, where an exception is a statement about risk.
- **For something you intend to fix this week.** Leave it red.
