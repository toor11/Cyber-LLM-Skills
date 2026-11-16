# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`race-conditions-and-concurrency-limit-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Double spend in snarkjs

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-362`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Double spend in snarkjs Double spend in snarkjs - **OSV ID**: GHSA-xp5g-jhg3-3rg2 - **CVE**: CVE-2023-33252 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N - **Published**: 2023-05-22T00:30:20Z - **Modified**: 2023-11-08T04:12:40.305994Z - **Affected Packages**: snarkj
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Double spend in snarkjs

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-362`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** iden3 snarkjs through 0.6.11 allows double spending because there is no validation that the publicSignals length is less than the field modulus.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
