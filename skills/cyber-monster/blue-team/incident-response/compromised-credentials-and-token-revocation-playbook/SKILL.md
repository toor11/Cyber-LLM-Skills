---
name: compromised-credentials-and-token-revocation-playbook
description: Executes enterprise-wide credential, OAuth refresh-token, PRT, Kerberos `krbtgt` (double-reset spacing), and cloud STS session revocation without locking out responder jump-hosts. Use when active identity or session-token compromise is confirmed.
family: incident-response
tier: core
triggers: ["token revocation playbook", "krbtgt double reset", "revoke refresh tokens", "identity containment order"]
cwe: [CWE-384]
owasp: []
attack: []
capec: []
related: [incident-response-playbooks, ir-triage-and-timeline, containment-and-eradication, ransomware-response]
corpus_sparse: true
---

# Compromised Credentials and Token Revocation Playbook - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Incident Response`](../README.md) | Tier: **core** | Paired Counterpart: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Modern identity issues several independent artefacts for one authentication, and each has its own revocation primitive, its own propagation delay and its own cache. A password reset invalidates the password. It does not invalidate the Kerberos TGT derived from it, the OAuth refresh token a client already holds, the primary refresh token on a joined device, or the cloud STS session assumed from a federated sign-in. That is why a reset alone reliably fails: the actor keeps a working artefact, often for the full lifetime of the longest-lived token in the chain, and continuous access evaluation only closes the gap for relying parties that participate in it and within its propagation window. Two spacing rules make the Kerberos case specific. The `krbtgt` account carries a two-password history, so a single reset still validates TGTs signed with the previous key and a second reset is required; and the two resets must be separated by more than the configured maximum ticket lifetime (ten hours at the default) so the first reset has replicated to every writable domain controller, with read-only controllers handled separately. The precondition that determines whether a revocation order is safe is a working map of what depends on the credential being revoked: service accounts, scheduled tasks, device-joined sessions, line-of-business apps using certificate auth, and the responder's own jump path. Revocation in the wrong order takes out the responder, the backups or the domain, and those outages outlast the compromise.

- **CWE-384 (Session Fixation):** Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the actor is believed to hold a Kerberos TGT or a service-account keytab **THEN** sequence the `krbtgt` double reset last, after credential resets and after the persistence sweep, because a reset while the actor still has a domain-wide foothold simply re-issues the target; and space the two resets more than the configured maximum ticket lifetime.
2. **IF** the actor holds an OAuth refresh token or a device PRT **THEN** revoke tokens at the issuer before resetting the password, and verify with a post-revocation sign-in attempt; a reset-first order leaves the token valid and signals the containment.
3. **IF** the environment is hybrid **THEN** decide explicitly whether on-premises authority or cloud authority is the source of truth for the affected principals, and revoke on both; a cloud-only revocation leaves the synchronised credential usable against on-premises services and vice versa.
4. **IF** the revocation will touch service accounts, backup agents or device-joined sessions **THEN** enumerate the dependants first and stage replacements; **IF** it will touch the responder's own jump host or break-glass path **THEN** exclude it explicitly and record the exclusion as a named residual risk.
5. **IF** a legal hold or a regulatory clock is running **THEN** freeze sign-in and audit records before the first revocation, because revocation events become the containment evidence and the pre-revocation sign-in pattern is what proves the actor's reach.
6. **IF** telemetry source covering `revokeSignInSessions` / `krbtgt reset interval` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).
8. **IF** required preconditions for `compromised-credentials-and-token-revocation-playbook` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Evidence classes for token, ticket and session attestation |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Issuer-side revocation and verification entry points |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the artefact chain before revoking anything.** For each affected principal: password, Kerberos keys, refresh tokens, device PRTs, cloud sessions, application-specific tokens, certificates, and any service-account secret. For each, record the primitive that invalidates it and the maximum time it survives without that primitive. This table is the plan; without it, revocation is guesswork ordered by whichever console is open.
2. **Choose the order from dependency, not from severity.** Tokens and grants first (they are silent and fast to revoke), then passwords, then device trust, then `krbtgt` last. The exception is an actor with demonstrated domain-wide Kerberos forgery: then `krbtgt` is prioritised but still follows the persistence sweep, because a reset before eradication hands the actor a fresh target.
3. **Build the dependant baseline.** Enumerate service accounts, scheduled tasks, backup and monitoring agents, certificate-based apps and device-joined endpoints that authenticate with the credentials about to change. Record the expected failure mode for each; this baseline is what distinguishes a planned service interruption from a second compromise after the reset.
4. **State the stop condition.** Stop when every artefact in the chain has a revocation event, every dependant has either re-authenticated successfully or is documented as intentionally down, and no sign-in from the actor's infrastructure succeeds after the last revocation timestamp. For `krbtgt` specifically, stop when both resets are recorded, replication has completed to every writable controller, and the second reset is separated from the first by more than the maximum ticket lifetime.
5. **Prove it by issuer event plus failed re-use.** The proof is the revocation record at the issuing authority plus an attempted use of the old artefact that fails. A successful revocation call that returns a correlation id is the claim; the failed authentication is the proof. For cloud tokens, the propagation window must be stated, because a success minutes after revocation is expected and not evidence of a surviving token.

## Concrete Patterns

| Indicator / Artifact | Evidence class | What it proves |
|---|---|---|
| Refresh-token revocation record at the issuer with the principal identifier and timestamp | Identity provider audit event | The refresh path is closed; access tokens already minted may still be valid until their own expiry |
| `krbtgt` password-change event paired with a second change more than the maximum ticket lifetime later | Directory service event | A single reset leaves the previous key valid for existing TGTs; only the pair invalidates them |
| Successful authentication from a revoked artefact after the propagation window | Sign-in log with artefact or session identifier | The revocation did not reach that surface, which is the finding rather than a failed containment |
| Device PRT revocation event alongside the user session revocation | Device registration or token audit | User tokens and device tokens are separate; revoking one leaves the other usable for silent re-authentication |
| Service-account authentication failures clustering immediately after the reset | Directory or application authentication log | The dependant map was incomplete; these are the planned-outage vs second-compromise discriminator |
| `AssumeRole` or token-exchange success by a principal whose issuer record shows revocation | Cloud audit session event | A surviving path exists outside the issuer, typically a long-lived key or a cached session token |

## Worked Contrast

**Brittle / Single-Indicator or Missing-Telemetry Practice (`revokeSignInSessions`):**

```powershell
# ANTI-PATTERN: reset the password, call it containment, close the ticket.
# The refresh token issued an hour earlier still works.
# The device PRT was never revoked, so the joined device re-authenticates silently.
# On-premises accepts the synchronised old password until the next sync cycle.
```

**Behavior-Anchored Detection & Guarded Triage (`revokeSignInSessions` — CWE-384):**

```yaml
title: Verified Behavior Check - compromised-credentials-and-token-revocation-playbook
artefact_chain:
  refresh_tokens:    { primitive: issuer_revoke, max_survival: until_revoke }
  access_tokens:     { primitive: issuer_revoke_plus_cae, max_survival: "up to configured lifetime; CAE near real time" }
  device_prt:        { primitive: device_revoke, max_survival: until_revoke }
  kerberos_tgt:      { primitive: krbtgt_double_reset, max_survival: "two resets, spaced beyond max ticket lifetime" }
  on_prem_password:  { primitive: ad_reset_plus_sync, max_survival: until_replication }
ordering:
  - tokens_and_grants
  - passwords_both_authorities
  - device_trust
  - krbtgt_last_after_persistence_sweep
proof:
  - revocation event naming the artefact at the issuing authority
  - failed re-use of the old artefact after the propagation window
telemetry_gap_rule: |
  if issuer audit records are unavailable, the revocation cannot be attested;
  disposition is INCONCLUSIVE rather than contained
```

**Why this matters:** Pairs `revokeSignInSessions` with `krbtgt reset interval` context, filters documented admin baselines, and enforces telemetry-presence verification.

## When It Is NOT This Issue

- **Helpdesk-driven MFA reset after a lost device:** produces the identical method-change and session-revocation events. Discriminate with the ticket, the caller-verification record and whether the ticket originated from the user's normal channel.
- **Scheduled password expiry or a bulk rotation:** a policy-driven rotation invalidates sessions across the estate in a narrow window and reads as mass revocation. Check the policy schedule and the change record before treating the sign-in failures as compromise fallout.
- **Break-glass account use during a DR test:** the emergency identity authenticates from an unusual range and holds broad roles exactly as designed. Confirm the exercise calendar.
- **A stale token accepted by a legacy endpoint:** an old refresh token still honoured by a protocol endpoint that predates modern revocation produces post-revocation successes that are not actor activity. Attribute by endpoint and user-agent.
- **Certificate-based authentication surviving a password reset:** an app or device using certificate auth legitimately continues after the password change, and its success is not evidence that the reset failed. Enumerate certificate credentials in the artefact chain.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `revokeSignInSessions` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Artefact chain enumerated:** password, Kerberos keys, refresh tokens, device PRT, cloud sessions, certificates and service secrets were each listed with their revocation primitive and maximum survival time.
- [ ] **Order justified by dependency:** the sequence tokens, passwords, device trust, then `krbtgt` was applied or the documented exception for demonstrated forgery is stated.
- [ ] **Dependant map built:** service accounts, agents, certificate apps and joined devices that authenticate with the affected credentials were enumerated with expected failure modes.
- [ ] **Responder path preserved:** jump hosts, break-glass identities and out-of-band management were excluded explicitly and the exclusion recorded as a named residual.
- [ ] **Effect attested per artefact:** each revocation has an issuer-side event plus a failed re-use, and cloud-token propagation windows are stated rather than assumed instantaneous.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: compromised-credentials-and-token-revocation-playbook
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-384 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`incident-response-playbooks`](../incident-response-playbooks/SKILL.md) - Incident Response (flagship)
- [`ir-triage-and-timeline`](../ir-triage-and-timeline/SKILL.md) - Incident Response (core)
- [`containment-and-eradication`](../containment-and-eradication/SKILL.md) - Incident Response (core)
- [`ransomware-response`](../ransomware-response/SKILL.md) - Incident Response (flagship)
- [`business-email-compromise-response`](../business-email-compromise-response/SKILL.md) - Incident Response (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `compromised-credentials-and-token-revocation-playbook` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-384`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
