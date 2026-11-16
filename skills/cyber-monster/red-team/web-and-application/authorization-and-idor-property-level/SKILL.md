---
name: authorization-and-idor-property-level
description: Mass assignment and property level authorization. Covers writable fields that should be read-only, privilege flags in request bodies, and nested object property exposure. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["property level authorization", "mass assignment", "writable role field", "bopla"]
cwe: [CWE-915, CWE-639]
owasp: [A01:2021, A01:2025]
attack: [T1562]
capec: [CAPEC-122]
related: [authorization-and-idor, authorization-and-idor-object-level, authorization-and-idor-function-level, authorization-and-idor-tenant-isolation]
parent: authorization-and-idor
---

# Authorization and IDOR Property Level - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)

## Mechanism and Preconditions

Property level authorization fails when a write path binds client-supplied keys directly onto a domain object, so fields the caller should never control are updated anyway. A mass-assignment binder such as `setattr` over the request dict, an ORM `update(attributes)`, or a framework `fill()` accepts a body that includes `role`, `is_admin`, `balance`, `tenant_id`, or a nested privileged key, and persists them alongside the legitimate fields. The read side of the same class over-exposes properties beyond the documented contract. The decision that is missing is an allowlist boundary between the input shape and the domain model, not an input-encoding check. The attacker escalates privilege or alters server-derived state by adding fields the interface never sends. Confirmation is that an unlisted privileged field submitted in the body persists and reads back changed.

- **Precondition chain:** an update endpoint binds request keys onto the model without an input allowlist, a privileged or server-derived field is reachable through that binder, and the submitted value persists and takes effect.
- **Readable differential:** the update sent with only the intended fields versus the same update with an extra privileged field; a finding exists when the extra field persists and reads back changed, and it closes once a write DTO with an explicit allowlist rejects unknown fields.
- **Empirical grounding:** CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes and CWE-639 under OWASP Top 10:2025 A01 Broken Access Control, mapping to OWASP API Security Top 10:2023 API3 Broken Object Property Level Authorization; no leaf-specific CVE is in scope, so the BOPLA taxonomy anchors the guidance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match property-level authorization **THEN** start at parent class [`authorization-and-idor`](../authorization-and-idor/SKILL.md) (1 hop) for general triage
2. **IF** the update binds the whole request body onto the model **THEN** add a privileged field such as role and read it back to test the binder
3. **IF** a server-derived field such as balance or verified is reachable in the body **THEN** test whether a read-only property accepts a client value
4. **IF** the extra field is accepted via duplicate keys or parameter pollution **THEN** route to [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md)
5. **IF** the over-exposed key corrupts object state through a prototype key **THEN** route to [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md)
6. **IF** the writable field is a privileged claim inside a signed token **THEN** route to [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md)
7. **IF** the response exposes properties beyond the documented DTO **THEN** treat the read side as BOPLA over-exposure and record the leaked fields
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)
9. **IF** every unlisted field is rejected by an input schema and nothing privileged persists **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Extra field is accepted via parameter pollution or duplicate keys | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant is request-to-model binding across duplicate parameters |
| Over-exposed property is a prototype key corrupting object state | [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) | Invariant is safe key handling on object merge, not field authorization |
| Writable field is a privileged claim inside a signed token | [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) | Invariant is claim integrity rather than binder allowlisting |
| Need parent class methodology | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate every write that binds request data onto a model.** Find `setattr`, `update(attributes)`, `fill()`, or direct dict merges on update endpoints, and note which model each targets. The sink is the binder, not the field name.
2. **Catalogue the privileged and server-derived columns.** List fields such as `role`, `is_admin`, `balance`, `verified`, `tenant_id`, and any nested privileged key. These are the candidates to smuggle into the body.
3. **Capture a legitimate-update baseline.** Submit the update with only the UI fields and read the record back, recording the privileged fields' current values. This is the pre-state.
4. **Add one privileged field to the body.** Resend the update with a single extra field the interface never sends, such as `role=admin`, keeping the legitimate fields identical, then read the record back.
5. **Confirm persistence, not echo.** Verify the value changed in a fresh read and took effect, because a response that echoes the input without storing it is not the finding.
6. **Stop condition.** Halt when the extra field either (a) persists and takes effect, (b) is rejected by an input schema or silently dropped on every attempt, or (c) would require changing a real third party's privileged state to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an unlisted privileged field persisting and reading back changed after a self-service update, shown against the pre-state, plus the binder line that writes unlisted keys. A reflected value that does not persist, or a field the account legitimately owns, is not proof.
8. **Close with the structural fix.** Bind through an explicit write DTO that forbids unknown fields, separate input shape from the domain model, and never write privileged columns from a self-service path. Verify by resending the privileged field and confirming the schema rejects it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `role` or `is_admin` field in the request body persisting to the model | Proves mass-assignment over-binding on an ORM that writes unlisted columns |
| A server-derived field such as `balance` or `verified` accepting a client value | Proves a read-only property is treated as writable on the update path |
| A `setattr`, `update(attributes)`, or `fill()` over the raw request map | Proves the binder trusts client keys rather than an allowlisted DTO |
| A nested object such as `settings.tenant_id` smuggling a privileged key | Proves nested binding escapes a top-level field filter |
| A response exposing properties beyond the documented DTO | Proves broken object property level authorization on the read side (BOPLA) |
| Input validation absent or configured to ignore unknown fields | Proves there is no forbid-extra boundary between input and the domain model |

## Worked Contrast

**Vulnerable Mass Assignment / BOPLA (`setattr` over Request Dict):**

```python
@router.patch("/users/me")
def update_me(payload: dict, db=Depends(get_db), user=Depends(current_user)):
    for key, val in payload.items():
        setattr(user, key, val)  # Attacker sends {"role": "admin", "tenant_id": 2}
    db.commit()
```

**Fixed Explicit Write-DTO with `extra='forbid'`:**

```python
class UserSelfUpdateDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str
    timezone: str

@router.patch("/users/me")
def update_me(dto: UserSelfUpdateDTO, db=Depends(get_db), user=Depends(current_user)):
    user.display_name = dto.display_name
    user.timezone = dto.timezone
    db.commit()
```

**Why this matters:** Never bind raw request maps onto ORM/database models (`CWE-915` / OWASP API3:2023); separate writable input DTOs from privileged domain columns (`role`, `is_admin`, `balance`, `tenant_id`).

## When It Is NOT This Issue

- **Field echoed but not stored:** a response that reflects the extra key without persisting it has not changed server state and is not the finding.
- **Allowlist already rejects it:** an endpoint whose schema forbids unknown fields and returns a validation error is enforcing the boundary.
- **Field the account legitimately owns:** updating a property the caller is entitled to change is expected, not over-binding.
- **Privileged write requires admin:** a binder that accepts the field only for an admin session is behaving as intended.
- **Derived value recomputed:** a client-supplied balance or total that the server overwrites from authoritative data before persisting is cosmetic.
- **Read-side field intended public:** a response property documented as public is not over-exposure merely because it seems sensitive.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authorization-and-idor-property-level` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authorization-and-idor-property-level` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authorization-and-idor-property-level
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-915, CWE-639 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`authorization-and-idor`](../authorization-and-idor/SKILL.md) - Web and Application (flagship)
- [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authorization-and-idor-property-level` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-915, CWE-639, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 9 |
| Top sources | CYBER_CPT/gh_advisories (4), bugbounty-hunter-v1 (3), OffsecCyber (2), SecEval/owasp_wstg (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
