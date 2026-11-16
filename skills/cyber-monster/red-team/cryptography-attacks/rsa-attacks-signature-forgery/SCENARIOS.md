# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`rsa-attacks-signature-forgery`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: ENS DNSSEC Oracle Vulnerable to RSA Signature Forgery via Missing PKCS#1 v1.5 Padding Validation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-326`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # ENS DNSSEC Oracle Vulnerable to RSA Signature Forgery via Missing PKCS#1 v1.5 Padding Validation - **OSV ID**: GHSA-c6rr-7pmc-73wc - **CVE**: CVE-2026-22866 - **Published**: 2026-02-25T18:26:58Z - **Modified**: 2026-02-28T06:26:33.113306Z - **Affected Packages**: @ensdomains/en
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: ENS DNSSEC Oracle Vulnerable to RSA Signature Forgery via Missing PKCS#1 v1.5 Padding Validation

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-326`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact The 'RSASHA256Algorithm' and 'RSASHA1Algorithm' contracts fail to validate PKCS#1 v1.5 padding structure when verifying RSA signatures. The contracts only check if the last 32 (or 20) bytes of the decrypted signature match the expected hash. This enables Bleichenbacher
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
