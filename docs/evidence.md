# Evidence: the document, and comparing two of them

An assessment is evidence only if the same cluster produces the same answer and
the next one can be compared against it. That is what the JSON document and
`stathe diff` are for.

## `stathe diff`

The retest. "We fixed it" is a claim; a diff against the assessment that found
it is evidence.

```sh
stathe check --context production --json > 2026-q3.json
# ... the client does the work, a quarter passes ...
stathe check --context production --json > 2026-q4.json

stathe diff 2026-q3.json 2026-q4.json
```

```console
Before   2026-07-02 09:15 CEST  production  stathe v0.3.1  70 resources, 20 findings
After    2026-10-01 09:02 CEST  production  stathe v0.3.1  71 resources, 18 findings

FIXED (2)
  SC-06   high     clusterrolebinding/ci-runner-admin   grants cluster-admin to serviceaccount orders/ci-runner
  SC-07   high     web/deployment/web                   image "nginx:latest" uses a floating tag that can change under you

2 fixed, 0 new, 18 unchanged
```

| Flag | Meaning |
|---|---|
| `--fail-on-new` | Exit 1 when the later assessment has findings the earlier one did not |

Three things it will not do:

- **Count an accepted risk as fixed.** A finding that moved into `.stathe.yaml`
  appears under `ACCEPTED SINCE`, never under `FIXED`. It is the most
  flattering lie this tool could tell, so it is a test rather than an
  intention.
- **Hide that the tool changed.** If the two assessments came from different
  versions of stathe, the diff says so before the counts: a new finding can
  also be a check that did not exist before.
- **Treat an old file as equivalent.** A findings file from before the document
  format records neither its date nor what it was pointed at, and the diff and
  the report cover both say so instead of letting your report date stand in for
  the assessment date.

Findings are matched on ID, resource **and** detail. One deployment can hold
two SC-05 findings, and treating them as one would hide the one that is left
after the other is fixed.

## The JSON document

`check --json` emits one object, not a bare array:

```json
{
  "schema_version": 2,
  "stathe_version": "v0.3.1",
  "assessed_at": "2026-10-30T08:21:59Z",
  "source": "production",
  "resources_checked": 70,
  "findings": [ ... ],
  "accepted": [ ... ],
  "lapsed": [ ... ],
  "not_assessed": [ ... ]
}
```

Everything a reader needs before treating the file as evidence rather than as
output: which version looked at what, when, what was accepted and why, and what
was filtered out before the checks ran.

The findings are in a total order — risk, ID, resource, detail — so two
assessments of an unchanged cluster produce the same document and every line a
diff shows is a line that changed in the cluster. Only `assessed_at` moves
between two identical runs.

Version 1 was that bare array. `report` and `diff` still read it, and both say
on sight that it carries no record of the run behind it.

