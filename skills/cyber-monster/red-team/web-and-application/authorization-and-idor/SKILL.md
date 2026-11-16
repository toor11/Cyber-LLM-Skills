---
name: authorization-and-idor
description: "Finds broken object and function level authorization: IDOR across identifiers and verbs, horizontal and vertical privilege escalation, BOLA in APIs, forced browsing to privileged functions, and tenant isolation gaps. Use when a request references an object or action without an obvious ownership check."
family: web-and-application
tier: flagship
triggers: ["idor", "insecure direct object", "broken access control", "bole", "bola", "privilege escalation web", "authorization bypass"]
cwe: [CWE-639, CWE-862, CWE-863]
owasp: [A01:2021, A01:2025]
attack: [T1562]
capec: [CAPEC-122]
related: [authorization-and-idor-object-level, authorization-and-idor-function-level, authorization-and-idor-tenant-isolation, sql-injection]
---

# Authorization and IDOR - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **flagship** | Paired Counterpart: [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)

## Mechanism and Preconditions

This flagship covers the gap where the application proves who the caller is but never checks whether that caller may touch the specific object or invoke the specific function in the request. Authentication middleware runs and sets a principal, yet the data query or the action dispatch uses a request-supplied identifier or route without constraining it by ownership, role, or tenant. The security decision that is missing is an authorization predicate on every read and every mutation, not an input-parsing check, so escaping and validation are irrelevant. The attacker swaps an identifier, calls a privileged route, or edits a claim and operates on records or functions belonging to other principals. Confirmation is a two-principal differential: the same request, run as a caller who should be denied, returns or mutates another subject's state.

- **Precondition chain:** a route is authenticated but its data or action is selected by a request-controlled identifier, role, or tenant value, the handler omits an ownership or privilege check, and the response or side effect reveals or changes another principal's state.
- **Readable differential:** the same request issued as the owning principal versus as a non-owning principal; a finding exists when the non-owning caller still reads or mutates the resource, and it closes once every query and action is constrained by the caller's identity and role server-side.
- **Empirical grounding:** CWE-639 Authorization Bypass Through User-Controlled Key, CWE-862 Missing Authorization, and CWE-863 Incorrect Authorization under OWASP Top 10:2025 A01 Broken Access Control, which also maps to OWASP API Security Top 10:2023 API1 BOLA and API5 BFLA.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves an object reference such as an id or UUID **THEN** switch to [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) (1 hop)
2. **IF** the target specifically involves a privileged function or admin route **THEN** switch to [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) (1 hop)
3. **IF** the target specifically involves cross-tenant or organisation isolation **THEN** switch to [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) (1 hop)
4. **IF** the target specifically involves a writable field that should be read-only **THEN** switch to [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) (1 hop)
5. **IF** the reference is exposed through a GraphQL node or relation resolver **THEN** route to [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) for per-resolver checks
6. **IF** access depends on a JWT scope or claim the client can tamper **THEN** route to [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) because the claim must be verified
7. **IF** the mutation sets a field the server should derive **THEN** model it as over-binding and read [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)
9. **IF** a non-owning principal is refused on every object and function after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Reference is exposed through a GraphQL node or relation resolver | [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) | Invariant is per-resolver authorization, not a REST id check |
| Request mutates a field that should be read-only for the caller | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant is which fields are writable, a binding problem |
| Access depends on a JWT scope or claim the client can tamper | [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) | Invariant is signed-claim integrity, not an ownership WHERE clause |
| Target matches `authorization-and-idor-object-level` | [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `authorization-and-idor-function-level` | [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `authorization-and-idor-tenant-isolation` | [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `authorization-and-idor-property-level` | [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory every route that reads or mutates an object or invokes a function.** For each, record how the target is selected: a path id, a query parameter, a body field, a role claim, or a tenant value. The authorization decision belongs on each of these, so the inventory is the map of candidate gaps.
2. **Confirm authentication is present but separate it from authorization.** A decorator that proves identity does not constrain the object; note whether any ownership, role, or tenant predicate follows the identity check in the handler or the query.
3. **Provision two principals with a known gap.** Create an owning account and a non-owning account, record which objects and functions each legitimately holds, and note the ids that cross the boundary. Two accounts are what make the test unambiguous.
4. **Capture the owning baseline.** Run the request as the rightful principal and record the authorised response and any state change. This is the reference the non-owning run is compared against.
5. **Replay as the non-owning principal with one changed selector.** Swap the id, invoke the privileged route, or edit the claim, keeping everything else constant, and observe whether the resource is read or mutated. One changed selector keeps the result attributable.
6. **Stop condition.** Halt when the non-owning request either (a) returns or mutates the other principal's state, (b) is refused with a 403 or a uniform 404 across every selector tried, or (c) would require altering a real third party's production records to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a non-owning principal reading or changing another subject's object or invoking a privileged function, shown as a two-account differential with one changed selector, plus the handler or query line that lacks the ownership or role predicate. A 200 to your own object, or an error you cannot attribute, is not proof.
8. **Close with the structural fix.** Constrain every query and action by the caller's identity, role, and tenant server-side, return uniform 404s to avoid existence oracles, and centralise the check so no route can omit it. Verify by replaying the two-account differential against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A route authenticated with `@login_required` but with no ownership predicate | Proves authentication without authorization on any framework, the defining IDOR and BOLA gap |
| Another account's object id returning full data under the caller's session | Proves a missing per-object check rather than a parsing or input flaw |
| A mutation verb succeeding on an object the caller never created | Proves the write path shares the read path's missing authorization |
| A GraphQL `node(id)` or relation resolving across owner boundaries | Proves resolver-level authorization is absent on the GraphQL stack |
| A privileged function reachable by URL with the link only hidden in the UI | Proves function-level authorization is enforced client-side only (BFLA) |
| A request body field such as `role` or `tenant_id` accepted onto the model | Proves property-level over-binding, a sibling access-control invariant |
| A JWT scope or claim trusted without a server-side cross-check | Proves authorization delegated to a client-tamperable claim |

## Worked Contrast

**Vulnerable Authentication-Only Lookup (BOLA / IDOR):**

```python
@app.get("/api/documents/<int:doc_id>")
@login_required
def read_document(doc_id: int):
    # Authentication is enforced, but any logged-in user can read any tenant's doc_id
    doc = Document.query.filter_by(id=doc_id).first_or_404()
    return jsonify(doc.to_dict())
```

**Hardened Tenant- and Principal-Scoped Query:**

```python
@app.get("/api/documents/<int:doc_id>")
@login_required
def read_document(doc_id: int):
    doc = Document.query.filter_by(
        id=doc_id, tenant_id=current_user.tenant_id, owner_id=current_user.id
    ).first_or_404()
    return jsonify(doc.to_safe_dto())
```

**Why this matters:** Authentication (`@login_required` / `Depends(get_current_user)`) proves WHO the caller is; object-level authorization must constrain EVERY query/mutation `WHERE` clause by caller ownership and tenant.

## When It Is NOT This Issue

- **Self-only object:** a request that reads or changes only the caller's own records, with no cross-principal reach, is in-scope for that account and not a finding.
- **Uniform 404 on cross access:** a scoped query that returns the same 404 for a non-owned id as for a missing one is enforcing authorization and denying an existence oracle.
- **Shared resource by design:** an object intentionally readable by a group or public, documented as such, is not an authorization break when another member reads it.
- **Authorization enforced downstream:** a handler that reaches a shared service which then applies the ownership check has a compensating control in place.
- **Signed capability token:** an opaque, unguessable, server-signed reference that the server validates for ownership is not an IDOR merely because it appears in the URL.
- **Second factor or re-auth required:** a sensitive action that re-prompts for the current password or a fresh challenge before mutating is not reachable as another principal end to end.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authorization-and-idor` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authorization-and-idor` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authorization-and-idor
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-639, CWE-862, CWE-863 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authorization-and-idor` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-639, CWE-862, CWE-863`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 53 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (31), securecode-web (20), cyber-security/security-code (1), SecEval/owasp_wstg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
