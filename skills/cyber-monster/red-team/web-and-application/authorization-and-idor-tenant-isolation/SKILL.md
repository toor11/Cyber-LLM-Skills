---
name: authorization-and-idor-tenant-isolation
description: Multi-tenant isolation failures. Covers cross-tenant data access through shared identifiers, cached responses, subdomain confusion, and organization-scoped tokens. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["tenant isolation", "cross tenant", "multi tenant bypass", "organization id"]
cwe: [CWE-639, CWE-284]
owasp: [A01:2021, A01:2025]
attack: [T1562]
capec: [CAPEC-122]
related: [authorization-and-idor, authorization-and-idor-object-level, authorization-and-idor-function-level, authorization-and-idor-property-level]
parent: authorization-and-idor
---

# Authorization and IDOR Tenant Isolation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)

## Mechanism and Preconditions

Tenant isolation fails when the boundary between organisations is enforced by a value the caller can influence rather than by a binding derived from the authenticated principal. A handler reads the tenant from an `X-Org-Id` header, an `org` parameter, a JWT claim, or a subdomain and queries `WHERE org_id = <that value>`, so a user of one tenant names another tenant and receives its data. The same failure appears when a shared cache keys a response without the tenant, serving one organisation's content to another, or when an organisation-scoped token is accepted on a different organisation's host. The attacker crosses the tenant boundary and reads or changes another customer's records. Confirmation is that a request authenticated for one tenant returns another tenant's state when the tenant selector is switched.

- **Precondition chain:** the tenant scope of a query, cache key, or token is taken from a caller-influenced value rather than bound to the principal, the handler trusts that value, and switching it reaches another tenant's data.
- **Readable differential:** the request made with the caller's own tenant selector versus the same request with another tenant's selector under the same credential; a finding exists when the switched selector returns the other tenant's data, and it closes once the tenant is derived from the principal binding server-side.
- **Empirical grounding:** CWE-639 Authorization Bypass Through User-Controlled Key and CWE-284 Improper Access Control under OWASP Top 10:2025 A01 Broken Access Control, aligning with the cross-tenant form of OWASP API Security Top 10:2023 API1 BOLA; no leaf-specific CVE is in scope, so the multi-tenant taxonomy anchors the guidance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match tenant isolation **THEN** start at parent class [`authorization-and-idor`](../authorization-and-idor/SKILL.md) (1 hop) for general triage
2. **IF** the tenant is taken from an X-Org-Id header or org parameter **THEN** switch the org selector under one credential to test cross-tenant reach
3. **IF** an organisation-scoped token is presented on another organisation's host **THEN** test whether the token is accepted where its org claim does not match
4. **IF** a response is cached under a key that omits the tenant **THEN** model it as a shared-cache bleed and read [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md)
5. **IF** the tenant is selected by a Host or subdomain the client controls **THEN** route to [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) for trusted tenant resolution
6. **IF** tenant scope is carried in a JWT claim the client can edit **THEN** route to [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md)
7. **IF** a cross-tenant object id resolves under one tenant's token **THEN** test the object query separately because it may omit the tenant predicate
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)
9. **IF** switching the tenant selector returns only the caller's own tenant data **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Cross-tenant leak comes from a response cached across tenants | [`web-cache-poisoning-and-deception-unkeyed-input`](../web-cache-poisoning-and-deception-unkeyed-input/SKILL.md) | Invariant is tenant-keyed caching, a cache-key problem |
| Tenant is selected by a Host or subdomain the client controls | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Invariant is trusted tenant resolution, not a row filter |
| Tenant scope is carried in a JWT claim the client can edit | [`jwt-attacks-claim-tampering`](../jwt-attacks-claim-tampering/SKILL.md) | Invariant is signed tenant-claim integrity |
| Need parent class methodology | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Trace where the tenant for each request is decided.** Determine whether the org comes from a header, a parameter, a JWT claim, a subdomain, or a server-side binding to the principal. The sink is any decision that reads the tenant from a caller-influenced source.
2. **Separate tenant derivation from the object query.** A query may be correctly owner-scoped yet take the tenant from the request, or correctly tenant-bound yet cache without the tenant. Note each path independently.
3. **Provision two tenants with known data.** Create an account in tenant A and one in tenant B, record a resource id visible in each, and note the selector that distinguishes them.
4. **Capture the own-tenant baseline.** Issue the request with the caller's rightful tenant selector and record the authorised response. This is the reference for the switch.
5. **Switch the tenant selector under the same credential.** Change the `X-Org-Id`, `org` parameter, host, or claim to tenant B while authenticated as tenant A, keeping everything else constant, and observe whether tenant B's data returns. For the cache path, compare responses across two tenant sessions on the same key.
6. **Stop condition.** Halt when the switched selector either (a) returns or mutates another tenant's data, (b) is confined to the caller's own tenant for every selector and cache probe, or (c) would require altering a real customer's records to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is another tenant's data returned under a credential bound to a different tenant, shown by switching only the tenant selector against the baseline, plus the line that sourced the tenant from the request or the cache key that omitted it. Access to your own tenant, or a cache hit without cross-tenant content, is not proof.
8. **Close with the structural fix.** Derive the tenant strictly from the authenticated principal binding, add the tenant predicate to every query, include the tenant in every cache key, and reject tokens whose org claim does not match the resolved tenant. Verify by replaying the selector switch against the hardened build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `X-Org-Id` or an `org` parameter honoured from the request | Proves tenant scope is caller-supplied rather than bound to the principal |
| A response cached under a tenant-agnostic key served across tenants | Proves the cache key omits the tenant, leaking data on shared CDNs or application caches |
| A bearer token whose org claim differs from the host it is accepted on | Proves tenant resolution trusts the token claim over a verified binding |
| A SQL `WHERE org_id = <request value>` sourced from input | Proves the isolation predicate is attacker-controlled |
| A neighbour tenant's resource ids returning 200 under one tenant's token | Proves missing cross-tenant authorization on the object query |
| Subdomain or Host used to select the tenant without re-validating the credential | Proves subdomain confusion in multi-tenant routing |

## Worked Contrast

**Vulnerable pattern:**

```python
def get_report(request):
    # Tenant scope is taken from a client-supplied header, so any org id works
    org_id = request.headers.get("X-Org-Id")
    return db.query(
        "SELECT * FROM reports WHERE id = %s AND org_id = %s",
        (request.args["id"], org_id),
    )
```

**Hardened pattern:**

```python
def get_report(request, principal):
    # Tenant is bound to the authenticated principal, never read from the request
    row = db.query_one(
        "SELECT * FROM reports WHERE id = %s AND org_id = %s",
        (request.args["id"], principal.org_id),
    )
    if row is None:
        abort(404)
    return row
```

**Why this matters:** The defect sources the tenant from a header the caller controls, so switching X-Org-Id reaches another organisation's rows even though the query looks scoped. The control derives the tenant from the authenticated principal binding and returns a uniform 404, so the isolation predicate can no longer be chosen by the attacker.

## When It Is NOT This Issue

- **Selector switch stays in-tenant:** a request where changing X-Org-Id returns only the caller's own tenant data is enforcing isolation server-side.
- **Tenant derived from the principal:** an app that ignores the request selector and scopes by the session's bound org is behaving correctly.
- **Cache key includes the tenant:** a shared cache that keys on tenant plus path does not bleed across organisations.
- **Shared global resource:** a catalogue or reference dataset intentionally common to all tenants is not a cross-tenant leak.
- **Token rejected on foreign host:** an org-scoped token refused when presented on another tenant's host has the binding check in place.
- **Self-owned data across your own tenants:** reaching data in a tenant the researcher legitimately belongs to is in-scope, not isolation failure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authorization-and-idor-tenant-isolation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authorization-and-idor-tenant-isolation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authorization-and-idor-tenant-isolation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-639, CWE-284 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`authorization-and-idor`](../authorization-and-idor/SKILL.md) - Web and Application (flagship)
- [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-function-level`](../authorization-and-idor-function-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authorization-and-idor-tenant-isolation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-639, CWE-284, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | hackerone_disclosed_reports (2), CYBER_CPT/gh_advisories (1), CYBER_CPT/wiz_research (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
