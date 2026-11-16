# Operational Triage and Response Playbook

> Sub-skill: [`custom-secret-scanner-detector-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a confirmed secret exposure. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A detector reports a credential on a production path.
- A report artifact is found to contain a plaintext secret.
- Alert volume from fixtures makes the queue unreadable.
- A credential is found in history after being rotated once already.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Live-shaped token on a non-fixture path | Confirmed exposure | Rotate first, then scrub; scrubbing history without rotation fixes nothing |
| Plaintext secret inside a report artifact | Disclosure | Delete the artifact, rotate, and fix the redaction path before re-scanning |
| Findings dominated by `tests/` paths | Precision defect | Add scoped allowlists; never disable the rule |
| Same fingerprint across many commits | Duplicate reporting | Deduplicate and report the earliest introducing commit |
| Token matches but entropy just above the floor | Marginal match | Verify against the issuer's format before paging anyone |

## Containment and Recovery

1. **Preserve before mutating:** record the fingerprint, path, line, and earliest commit — never the plaintext. The fingerprint is what lets the rotation owner confirm the same credential without handling it again.
2. **Check blast radius:** search the same fingerprint across all repositories and CI artifacts; a secret committed once is usually copied into build logs and caches.
3. **Eradicate the root cause:** rotate the credential, remove it from the build artifacts, and add the shape to the detector's fixtures so a recurrence is caught before merge.
