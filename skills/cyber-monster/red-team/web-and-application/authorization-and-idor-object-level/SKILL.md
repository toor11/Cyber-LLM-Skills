---
name: authorization-and-idor-object-level
description: IDOR at the object level. Covers enumerable and guessable identifiers, UUID leakage, sequential IDs, and cross-tenant object access across REST, GraphQL and file endpoints. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["idor object", "bola", "object level authorization", "id enumeration"]
cwe: [CWE-639, CWE-284]
owasp: [A01:2021, A01:2025]
attack: [T1562]
capec: [CAPEC-122]
related: [authorization-and-idor, authorization-and-idor-function-level, authorization-and-idor-tenant-isolation, authorization-and-idor-property-level]
parent: authorization-and-idor
---

# Authorization and IDOR Object Level - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)

## Mechanism and Preconditions

Object level authorization fails when a handler selects a record by a client-supplied reference and runs the query without constraining it to the caller's ownership. Sequential integers, leaked UUIDs, or references echoed from other responses let a user name an object they do not own, and because the only check was authentication the row is returned or mutated. The reference may be a database id, a file path, a GraphQL global id, or a batch element, but the invariant is identical: possession of the reference is treated as authorization. The attacker reads or changes other users' records at scale by walking or substituting references. Confirmation is that a reference belonging to another owner resolves to full data under the caller's own credential.

- **Precondition chain:** a handler fetches an object by a request-controlled reference, the query lacks an ownership predicate, and the reference for other owners is guessable, enumerable, or leaked so the caller can name it.
- **Readable differential:** the caller's own object reference versus a neighbour's reference under the same credential; a finding exists when the neighbour's reference returns data, and it closes once the query is scoped by owner and returns a uniform 404 for non-owned references.
- **Empirical grounding:** CWE-639 Authorization Bypass Through User-Controlled Key and CWE-284 Improper Access Control under OWASP Top 10:2025 A01 Broken Access Control, mapping to OWASP API Security Top 10:2023 API1 Broken Object Level Authorization, with BOLA testing described in the OWASP WSTG.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match object-level authorization **THEN** start at parent class [`authorization-and-idor`](../authorization-and-idor/SKILL.md) (1 hop) for general triage
2. **IF** the reference is a sequential integer id **THEN** walk id plus or minus one under one credential to test for a neighbour read
3. **IF** the reference is a UUID surfaced in another response or listing **THEN** follow the leaked UUID to test whether unguessability was the only control
4. **IF** the object is a file fetched by path rather than a database row **THEN** reclassify toward path handling and read [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md)
5. **IF** the reference is a GraphQL global id passed to a node query **THEN** route to [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md)
6. **IF** the object is returned by a REST or gRPC API keyed on id **THEN** route to [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) for per-object authorization at the API layer
7. **IF** a mutation verb on a neighbour reference also succeeds **THEN** test the write path separately because it may share the missing check
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)
9. **IF** every non-owned reference returns a uniform 404 under the caller's credential **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Object id is referenced through a GraphQL node query | [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) | Invariant is resolver ownership checks on the node, not a REST path |
| Object is a file fetched by path rather than a database row | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | Invariant shifts to path canonicalisation and storage scoping |
| Object is returned by a REST or gRPC API keyed on id | [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) | Invariant is per-object authorization at the API layer (BOLA) |
| Need parent class methodology | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate every read and write that selects an object by a client reference.** Record whether the reference is a sequential id, a UUID, a path, or a GraphQL global id, and where it enters the query. The sink is the query that lacks the owner predicate.
2. **Determine how references for other owners can be obtained.** Sequential ids are enumerable, UUIDs may leak in listings or other responses, and paths may be predictable. Reachability of the reference is part of the precondition.
3. **Provision two owners with known references.** Record one object the caller owns and one owned by another account, so the boundary id is unambiguous.
4. **Capture the owning baseline.** Fetch or mutate the caller's own reference and record the authorised response and any change. This is what the neighbour run is compared against.
5. **Substitute the neighbour reference under the same credential.** Request or mutate the other owner's reference, keeping the credential and everything else constant, and observe whether the row resolves. A full-data response is the signal.
6. **Stop condition.** Halt when the neighbour reference either (a) returns or mutates another owner's record, (b) is refused with a uniform 404 or 403 for every reference form, or (c) would require altering a real third party's records to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a non-owned reference resolving to full data or a mutation under the caller's credential, shown against the owning baseline, plus the query line missing the `owner_id` constraint. A 404 that matches the missing-object response, or access to your own object, is not proof.
8. **Close with the structural fix.** Add the ownership predicate to every object query and mutation, return a uniform 404 so presence cannot be inferred, and prefer unguessable references as defence in depth rather than as the control. Verify by replaying the neighbour reference against the scoped query.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Sequential ids (`/invoices/5001` then `/5002`) returning different owners' rows | Proves enumerable object references with no ownership predicate on the data query |
| A UUID surfaced in one response resolving to its owner's data elsewhere | Proves that unguessability was the only control rather than authorization |
| A file-download route keyed solely by an object id or path | Proves object access decided by reference possession rather than ownership |
| A batch or GraphQL node query returning multiple owner_ids | Proves the batching path bypasses the per-object check on the API stack |
| Distinct-id access rate for one token far above its baseline | Proves enumeration behaviour consistent with BOLA sweeping |
| A 200 for a neighbour id where a scoped query would return 404 | Proves the WHERE clause lacks the owner_id constraint |

## Worked Contrast

**Vulnerable Primary-Key-Only Lookup:**

```python
row = db.execute(
    text("SELECT id, secret_notes FROM invoices WHERE id = :id"), {"id": invoice_id}
).mappings().first()
```

**Fixed Composite Ownership + Uniform 404 Constraint:**

```python
row = db.execute(
    text("SELECT id, secret_notes FROM invoices WHERE id = :id AND owner_id = :uid"),
    {"id": invoice_id, "uid": current_user.id},
).mappings().first()
if row is None:
    raise HTTPException(status_code=404)
```

**Why this matters:** Scoping the SQL predicate by `owner_id` (and returning uniform 404s) eliminates both unauthorized reads and cross-tenant existence oracles.

## When It Is NOT This Issue

- **Uniform 404 for non-owned ids:** a scoped query that returns the same 404 for a neighbour id as for a missing id denies both access and the existence oracle.
- **Own object accessed:** resolving the caller's own reference is expected and not a cross-owner read.
- **Shared or public object:** a reference intentionally readable by a group, such as a published document, is not BOLA when another member reads it.
- **Signed reference validated for ownership:** an opaque server-signed id that the server checks against the owner is not an IDOR merely because it is in the URL.
- **Reference not reachable:** a UUID that is never leaked and cannot be guessed is not exploitable even if the query lacks the predicate, pending a leak path.
- **Downstream ownership filter:** a handler that reaches a service applying the owner check has a compensating control and no cross-owner exposure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authorization-and-idor-object-level` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authorization-and-idor-object-level` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authorization-and-idor-object-level
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-639, CWE-284 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`authorization-and-idor`](../authorization-and-idor/SKILL.md) - Web and Application (flagship)
- [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authorization-and-idor-object-level` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-639, CWE-284, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 7 |
| Top sources | securecode-web (8), CYBER_CPT/go_exploitdb (2), CYBER_CPT/osv (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 4 code / 0 det / 0 tools / 11 cases |
| Grounding | multi-dataset corpus-grounded |
