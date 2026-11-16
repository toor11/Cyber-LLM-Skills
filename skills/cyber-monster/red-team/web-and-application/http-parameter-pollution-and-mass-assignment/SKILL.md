---
name: http-parameter-pollution-and-mass-assignment
description: Exploits duplicate and nested parameters plus over-permissive model binding to bypass validation, escalate privileges and flip logic. Use when the framework merges repeated parameters or binds request bodies to objects.
family: web-and-application
tier: leaf
triggers: ["parameter pollution", "hpp", "mass assignment", "object injection", "autobinding", "overposting"]
cwe: [CWE-235, CWE-915]
owasp: [A01:2021, A08:2021]
attack: []
capec: [CAPEC-460]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Http Parameter Pollution and Mass Assignment - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This technique abuses two framework conveniences that both decide which bytes of a request become trusted fields. In parameter pollution, the same key is sent more than once or in an array or nested form, and a front-end proxy, a WAF, and the application each pick a different occurrence, so a value that passed inspection is not the value the handler finally reads. In mass assignment, a model binder copies every submitted key onto an object, so a caller can set fields the UI never exposes, such as a role, an ownership id, a price, or an account balance. The security decision lives in the binding and merge layer, not in any escaping routine, so the attacker gains privilege, flips logic, or writes a server-authoritative field by naming it directly. Confirmation is a persisted change to a field the interface could never set, or a divergence between what two parsers believe a parameter equals.

- **Precondition chain:** A request field is either merged from duplicate or nested occurrences by more than one parser, or bound wholesale onto an object by an auto-binder, the application reads a field it should have derived server-side, and the resulting write moves privilege, ownership, or an economic value in the caller's favour.
- **Readable differential:** The same update sent with only the interface's fields versus the same update with an extra authority field or a duplicated parameter; a finding exists when the server-side record changes for the polluted or over-posted version and reverts once the binder is restricted to an explicit allowlist.
- **Empirical grounding:** CWE-235 Improper Handling of Extra Parameters and CWE-915 mass assignment anchor this class; OWASP Top 10:2025 splits the impact across A01:2025 Broken Access Control and A06:2025 Insecure Design. SOURCES.md lists no HPP or mass-assignment specific advisory, so this slug stays at the taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a duplicated or array parameter is parsed differently by the proxy, the WAF, and the app **THEN** treat the parser disagreement as the primary finding and compare which occurrence each tier reads
2. **IF** a model binder copies the whole request body onto an object **THEN** treat over-posting as the primary finding and drive the explicit allowlist fix before anything else
3. **IF** duplicate parameters split across two HTTP parsers more than they over-post a model **THEN** switch to [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) for the normalization angle
4. **IF** a nested key such as __proto__ or constructor reaches an object merge **THEN** switch to [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) because the invariant is prototype integrity, not field authority
5. **IF** an over-posted id or ownership field reaches another principal's row **THEN** switch to [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) because the invariant is per-property access control
6. **IF** the over-posted field is a price, discount, or total **THEN** confirm the amount server-side and read [`business-logic-flaws-payment-and-pricing`](../business-logic-flaws-payment-and-pricing/SKILL.md) for the settlement invariant
7. **IF** the extra field only exists after discovering a hidden parameter **THEN** first enumerate it with [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** every authority field is server-derived and unknown keys are rejected by the schema **THEN** STOP and record a verified non-finding rather than reporting an accepted-but-ignored parameter

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Duplicate parameters are split differently by two parsers | [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) | Invariant is parser agreement on one value, not which fields are server-authoritative |
| A nested key pollutes a shared object prototype | [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) | Invariant is prototype integrity, a different sink from model binding |
| A bound field reaches another principal's record | [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) | Invariant is per-property access control rather than over-posting |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the binder and the merge order.** Read the controller and model layer for the call that maps request keys to object fields (a `ModelAttribute`, `update_attributes`, spread into an options object, or a bulk `setattr`). Separately note every tier that reparses the query or body, because pollution lives wherever two tiers disagree.
2. **Classify the finding shape from evidence.** If one key accepted twice yields two different effects, you are in parameter pollution. If an unexposed field is accepted and persisted, you are in mass assignment. Decide from an observed write, not from the HTML form.
3. **Inventory server-authoritative fields.** List the fields the server must derive itself: role, tenant or owner id, price, status, verified flags, timestamps. These are the candidate over-post targets; a UI-editable field being writable is not a finding.
4. **Record an intended-path baseline.** Submit the update exactly as the interface would and read the resulting object back from the API, capturing each authority field's stored value. This is the record a probe must move.
5. **Apply one polluted or over-posted variant.** Add a single authority field, or duplicate one key with a second value, holding everything else constant, then read the object back. A changed reflected message with an unchanged stored field is not the finding.
6. **Stop condition.** Halt when the variant either (a) persists a change to an authority field or makes two parsers read different values, and reverts when the binder is allowlisted, (b) is accepted but ignored with no stored change across two baselines, or (c) would require writing to another live user's record to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a persisted before-and-after difference in a server-authoritative field tied to one added or duplicated key, plus the exact binder line that copied the client value. A 200 response, an echoed field, or a value the next read recomputes away is not proof.
8. **Close with the structural fix.** Replace wholesale binding with an explicit field allowlist, keep every authority field server-derived, and normalise duplicate parameters to one canonical occurrence at the edge so no two tiers disagree. Verify by replaying the intended-path baseline and the over-post variant against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An update endpoint accepts a `role`, `isAdmin`, or `owner_id` field that no form renders | Proves the model binder is open on frameworks such as Rails, Spring `@ModelAttribute`, Django, or Express, so a derived field is client-writable |
| The same key sent twice changes behaviour between the WAF verdict and the app | Proves a parser differential where the inspected occurrence and the consumed occurrence differ on any proxy-fronted stack |
| An array form like `a[]=1&a[]=2` collapses to a different scalar at the app than at the edge | Proves list-versus-scalar coercion disagreement, typically PHP, Node querystring, or Rails parameter parsing |
| A hidden `price`, `discount`, or `status` field is persisted after a profile or order write | Proves an economic or state field is bound from the request rather than recomputed server-side |
| A JSON body with an extra key succeeds where the documented schema omits it | Proves no strict schema rejects unknown fields on the API tier, a precondition for over-posting |
| Changing a `created_at`, `verified`, or `tenant_id` value through a normal update call | Proves lifecycle or tenancy fields are writable, which breaks isolation rather than mere validation |
| Two values for one key resolve to first-wins at one hop and last-wins at another | Proves order-dependent selection that lets an attacker satisfy a filter while changing the effective value |

## Worked Contrast

**Vulnerable pattern:**

```python
# Binds every request key onto the model, so role/owner_id ride in via over-posting
def update_profile(request, user):
    for key, value in request.POST.items():
        setattr(user, key, value)        # role, is_staff, tenant_id all writable
    user.save()
    return user
```

**Hardened pattern:**

```python
EDITABLE = {"display_name", "bio", "avatar_url"}

def update_profile(request, user):
    # Only interface-editable fields are bound; authority fields stay server-derived
    unknown = set(request.POST) - EDITABLE
    if unknown:
        raise ValueError("unexpected fields: %s" % sorted(unknown))
    for key in EDITABLE & request.POST.keys():
        setattr(user, key, request.POST[key])
    # role, is_staff and tenant_id are never taken from the request body
    user.save()
    return user
```

**Why this matters:** The vulnerable binder trusts the request to decide which fields are writable, so authority fields are over-posted. The fix inverts the decision: an explicit allowlist governs binding, unknown keys are rejected, and server-authoritative fields are never sourced from the body.

## When It Is NOT This Issue

- **Accepted but ignored parameter:** an extra key that the handler reads into a throwaway dict and never persists is not a finding; only a stored change to an authority field counts.
- **UI-editable field being writable:** a `display_name` or `bio` that the form already exposes is meant to be bound; over-posting it changes nothing about the trust model.
- **Strict schema already rejects unknowns:** an API that returns 400 on an undeclared field has the structural control in place, so the accepted-field theory is closed.
- **Duplicate parameter with identical effect:** if every tier reads the same occurrence and the result is unchanged, there is no parser differential to exploit.
- **Self-only object:** over-posting a field on the attacker's own draft or session with no cross-user, billing, or privilege effect is a sandbox quirk, not escalation.
- **Framework strong-parameters in force:** a Rails `permit` list or DRF serializer that drops the extra field means the value never reaches the model, so the write cannot occur.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-parameter-pollution-and-mass-assignment` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-parameter-pollution-and-mass-assignment` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-parameter-pollution-and-mass-assignment
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-235, CWE-915 | Mapping: A01:2021, A08:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-parameter-pollution-and-mass-assignment` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-235, CWE-915`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 49 |
| Distinct dataset sources | 13 |
| Top sources | OffsecCyber (15), CYBER_CPT/gh_advisories (10), bugbounty-hunter-v1 (4), SecEval/owasp_wstg (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 11 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
