---
name: cloud-incident-response-identity-containment
description: Cloud identity containment. Covers revoking sessions and keys, disabling principals and rebuilding trust without destroying evidence. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: incident-response
tier: leaf
triggers: ["cloud identity containment", "revoke access key", "disable principal"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [cloud-incident-response, cloud-incident-response-audit-reconstruction, incident-response-playbooks, ir-triage-and-timeline]
parent: cloud-incident-response
---

# Cloud Incident Response Identity Containment - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **leaf** | Paired Counterpart: [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md)

## Mechanism and Preconditions

Cloud containment fails for one predictable reason: the operator reasons about credentials when the actor is holding a session. Disabling an IAM user removes the ability to authenticate but leaves every assumed-role session already issued with that user's trust intact until the session's own expiry. Deleting an access key invalidates that key only; a second key created hours earlier, a role chained from it, or a service principal holding a client secret continues unaffected. Revoking a refresh token at the identity provider terminates the refresh path, but an access token already minted remains valid until its own lifetime expires or an issuer-driven revocation event reaches the relying party. The containable unit is therefore not the identity but the set of live artifacts derived from it — keys, role sessions, delegated grants, workload-identity tokens, and the trust relationships that let a new artifact be minted after containment. Two preconditions make the work tractable. First, session-level attribution must be possible, which means records identify the specific session (`accessKeyId` on a role assumption, a token identifier at the issuer) rather than only the principal. Second, a control path must exist that the containment does not sever — a break-glass identity, an out-of-band management role, or a separate administrative account — because cloud revocation is broad by construction and will as readily lock out the responder as the actor.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `cloud-incident-response-identity-containment` **THEN** start at parent class [`cloud-incident-response`](../cloud-incident-response/SKILL.md) first.
2. **IF** the actor used a long-lived access key **THEN** deactivate every key on the principal before deleting any of them, and enumerate keys on all principals the compromised one could have touched; **IF** the actor used an assumed role **THEN** attach a session-revocation policy keyed to token issue time instead, because the underlying credential deletion does not terminate the session.
3. **IF** the credential originated at a federated identity provider or CI system **THEN** revoke at the issuer; the cloud provider cannot invalidate a token it never minted, and containment that stops at the cloud boundary leaves a working path.
4. **IF** containment will remove the responder's own authority, a break-glass identity, or the last administrative path **THEN** stage a replacement first and prove it works, then contain.
5. **IF** a legal hold, insurer request or regulatory clock is running **THEN** freeze the identity records and session inventory before revocation changes them, since revocation event timestamps become the containment proof.
6. **IF** telemetry source covering `revoke key` / `disable user` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md).
8. **IF** required preconditions for `cloud-incident-response-identity-containment` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`cloud-incident-response`](../cloud-incident-response/SKILL.md) | General class triage before variant specifics |
| Need to reconstruct what happened after containment | [`cloud-incident-response-audit-reconstruction`](../cloud-incident-response-audit-reconstruction/SKILL.md) | Timeline joining and reproducibility |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for session inventory and revocation proof |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Provider revocation and verification entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory the live artifacts, not the principals.** For each implicated identity, enumerate access keys with their creation dates and last-used timestamps, active role sessions with their session keys, OAuth consent grants, workload-identity bindings and trust relationships. An artifact with a creation date inside the window and no documented owner is persistence and is the first removal target.
2. **Choose the revocation primitive per artifact class.** Deactivate keys, attach a session-revocation deny keyed to token issue time for role sessions, revoke consent grants for app tokens, and revoke or delete tokens at the issuer for federated access. Record which primitive was applied to which artifact, because the proof obligation differs for each.
3. **Establish the pre-containment baseline for the principal.** Record its normal source addresses, user-agents and call cadence for the preceding two weeks. After containment, this baseline is what makes an `AccessDenied` from an unexpected address meaningful and a normal call from an expected one explicable.
4. **State the stop condition.** Stop when every enumerated artifact is either revoked or attributed to a documented owner, and when no successful call from any revoked artifact's session appears after its revocation timestamp beyond the propagation bound. A principal with one unattributed key remaining is not contained, regardless of how many others were removed.
5. **Prove effect from the audit record.** The proof is a revocation event in the audit log with the artifact identifier, plus either an observed `AccessDenied` or an absence of successful activity from that session after the timestamp. A console confirmation, an exit code of zero or a policy that was attached is the claim; the audit event is the proof.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| `CreateAccessKey` inside the window on a principal that already had keys | Management event | Persistence that survives deleting the key the actor arrived with; the creation event carries the actor's session key |
| Distinct `accessKeyId` values under one role ARN active in the same hour | Management event session field | Multiple simultaneous sessions, so revoking the role's trust alone leaves the live sessions running until expiry |
| `AttachRolePolicy` or `PutRolePolicy` on a role the responder does not administer | Management event | Privilege granted for re-entry, which must be reverted before revocation is meaningful |
| `CreateSAMLProvider`, `CreateOIDCProvider` or trust-policy edit adding an external principal | Management event | A federation path that mints fresh credentials after containment and is invisible to key-level revocation |
| `RemoveOAuth2PermissionGrant` or provider-side token revocation record | Authorization audit event | The grant path is closed, as opposed to merely unused |
| `AccessDenied` from the revoked session key after the revocation timestamp | Management event with error field | Revocation propagated and the actor's session is genuinely denied |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`revoke key`):**

```text
# ANTI-PATTERN: delete the one access key named in the alert, close the ticket.
# The actor assumed a role two hours earlier: that session keeps working.
# A second key created in the same window is untouched. The deny never lands
# because nothing was attached; the console said "deleted".
```

**Behavior-Anchored Detection & Guarded Triage (`revoke key` — CWE-778):**

```json
{
  "title": "Verified Behavior Check - cloud-incident-response-identity-containment",
  "artifact_inventory": {
    "long_lived_keys": "deactivate all, then delete after the window closes",
    "role_sessions": "attach deny keyed to aws:TokenIssueTime, then verify",
    "federated_tokens": "revoke at issuer; provider cannot invalidate foreign tokens",
    "consent_grants": "remove grant, then remove the refresh token"
  },
  "proof_required": {
    "event": "audit record naming the artifact identifier",
    "effect": "AccessDenied or absence of success after revocation timestamp",
    "propagation_bound": "approximately thirty seconds for policy-based denies"
  },
  "telemetry_gap_rule": "if session identifiers are absent from records, disposition is INCONCLUSIVE"
}
```

**Why this matters:** Pairs `revoke key` with `disable user` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **Scheduled credential rotation:** a secrets manager creates and deletes keys on a cadence, producing key-creation bursts that look like persistence. Compare against the rotation schedule and the owning workload.
- **A stale token accepted by a legacy endpoint:** an old key still in use by an unowned integration appears as an active session from an unexpected address. Attribute by user-agent and destination before treating it as the actor.
- **Break-glass account activity during a DR test:** the emergency identity signs in from an unusual address and assumes broad roles exactly as designed. Check the test calendar and the change record.
- **A pipeline assuming a shared role concurrently:** one role legitimately carries many parallel sessions during a deployment, and the session multiplicity is not multiple actors. Correlate with the pipeline run ids.
- **Helpdesk-driven credential reset:** a legitimate reset produces the method-change and session-revocation events that containment also produces. Confirm the ticket and the caller verification.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `revoke key` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Artifact inventory complete:** keys, role sessions, consent grants, workload-identity bindings and trust relationships were each enumerated for the implicated principals, not just the credential named in the alert.
- [ ] **Primitive matched to artifact:** each artifact class has a named revocation primitive, and issuer-side revocation was used where the cloud provider never minted the token.
- [ ] **Control path preserved:** a break-glass or out-of-band administrative path was verified reachable before broad revocation was applied.
- [ ] **Baseline recorded:** the principal's pre-containment source ranges, user-agents and cadence were captured, so post-containment denials and successes are interpretable.
- [ ] **Effect attested:** every revocation has an audit event naming the artifact identifier plus a post-revocation denial or absence of success, with the propagation bound stated.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: cloud-incident-response-identity-containment
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`aws-attacks`](../../../red-team/cloud-container-supply-chain/aws-attacks/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`cloud-incident-response`](../cloud-incident-response/SKILL.md) - Incident Response (core)
- [`cloud-incident-response-audit-reconstruction`](../cloud-incident-response-audit-reconstruction/SKILL.md) - Incident Response (leaf)
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-incident-response-identity-containment` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
