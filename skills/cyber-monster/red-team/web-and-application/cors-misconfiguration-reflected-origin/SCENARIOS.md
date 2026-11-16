# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cors-misconfiguration-reflected-origin`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: OpenClaw has an inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix ma

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-942`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary An authentication bypass in the optional 'voice-call' extension/plugin allowed unapproved or anonymous callers to reach the voice-call agent when inbound policy was set to 'allowlist' or 'pairing'. Deployments that do not install/enable the 'voice-call' extension are
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: OpenClaw has an inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix ma

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-942`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OpenClaw has an inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching) OpenClaw has an inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching) - **OSV ID**: GHSA-4rj2-gpmh-qq5x - **CVE**: CVE-2026-28446 -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Deno's improper suffix match testing for DENO_AUTH_TOKENS

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-942`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Deno improperly checks that an import specifier's hostname is equal to or a child of a token's hostname, which can cause tokens to be sent to servers they shouldn't be sent to. An auth token intended for 'example.com' may be sent to 'notexample.com'. ### Details [auth
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
