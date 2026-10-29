# Attacking Northwind

Northwind is a small logistics platform with ten deliberate weaknesses. This
walkthrough shows you how to demonstrate each one yourself, so that the baseline
that follows is a fix for something you have actually seen, rather than a
precaution against something abstract.

Everything here runs against your own local k3d cluster. Do not point any of it
at a cluster you do not own.

> **Status: not written yet.** The demo app is being built first. Each section
> below maps to a finding ID (NW-01 to NW-10) and will get a reproduction, an
> expected output, and the baseline change that closes it.

## Planned walkthroughs

| ID | Weakness |
|---|---|
| NW-01 | No network separation — reach the database from the public web pod |
| NW-02 | Images deployed without a vulnerability scan |
| NW-03 | Critical vulnerabilities in running images |
| NW-04 | Credentials stored in a ConfigMap |
| NW-05 | Privileged container, workloads running as root |
| NW-06 | Service account with cluster-admin |
| NW-07 | Mutable image tags |
| NW-08 | Unsigned images, origin cannot be verified |
| NW-09 | No resource limits |
| NW-10 | API audit logging not retained |
