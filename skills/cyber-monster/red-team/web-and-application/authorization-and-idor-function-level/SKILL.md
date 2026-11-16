---
name: authorization-and-idor-function-level
description: Broken function level authorization. Covers reaching privileged endpoints directly, verb and method tampering, role header trust, and admin routes protected only in the UI. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["function level authorization", "bfla", "admin endpoint bypass", "verb tampering", "route confusion"]
cwe: [CWE-285, CWE-862]
owasp: [A01:2021, A01:2025]
attack: [T1562]
capec: [CAPEC-122]
related: [authorization-and-idor, authorization-and-idor-object-level, authorization-and-idor-tenant-isolation, authorization-and-idor-property-level]
parent: authorization-and-idor
---

# Authorization and IDOR Function Level - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)

## Mechanism and Preconditions

Broken function level authorization is reached when a privileged action is gated only by how the user interface exposes it, not by a server-side role check on the endpoint itself. The admin route exists, the authenticated session is valid, but the handler never asserts that the caller holds the role the action requires, so a low-privilege user who knows or guesses the path invokes it directly. The same class appears as verb tampering, where a check applies to the exposed method but not to `PUT`, `DELETE`, or a method-override header, and as trust in a client-supplied role value. The attacker performs administrative operations such as creating users, granting roles, or deleting records. Confirmation is that a low-privilege principal successfully invokes the privileged function where only an administrator should.

- **Precondition chain:** a privileged endpoint or verb is authenticated but lacks a server-side role assertion, the caller can reach it directly or via an alternate method, and invoking it performs an action the caller's role should forbid.
- **Readable differential:** the privileged action invoked as an administrator versus as a low-privilege user; a finding exists when the low-privilege call succeeds, and it closes once the required role is enforced on every method of the endpoint server-side.
- **Empirical grounding:** CWE-285 Improper Authorization and CWE-862 Missing Authorization under OWASP Top 10:2025 A01 Broken Access Control, mapping to OWASP API Security Top 10:2023 API5 Broken Function Level Authorization; no leaf-specific CVE is in scope, so the BFLA taxonomy anchors the guidance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match function-level authorization **THEN** start at parent class [`authorization-and-idor`](../authorization-and-idor/SKILL.md) (1 hop) for general triage
2. **IF** an admin route is reachable by URL though the link is hidden in the UI **THEN** invoke the route directly as a low-privilege principal before anything else
3. **IF** a check applies to GET but not to PUT, POST, or DELETE on the same route **THEN** test each verb separately for an incomplete authorization gate
4. **IF** the stack honours a method-override header or _method parameter **THEN** test whether the override reaches a gated action
5. **IF** the privileged action is reached by swapping an object id rather than a route **THEN** reclassify as object access and read [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md)
6. **IF** the admin mutation is a GraphQL field with no resolver guard **THEN** route to [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md)
7. **IF** the bypass rides an unusual verb the router still dispatches **THEN** route to [`http-method-and-verb-attacks`](../http-method-and-verb-attacks/SKILL.md) for verb-complete enforcement
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md)
9. **IF** a batch item is authorized by one route's permission callback and executed by another route's handler **THEN** that is function-level authorization across a router boundary; patch-diff the index alignment and read [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md)
10. **IF** every privileged route and verb, including every batch item, refuses the low-privilege principal **THEN** STOP and record a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Privileged action is reached by swapping an object id, not a route | [`rest-and-grpc-api-security`](../rest-and-grpc-api-security/SKILL.md) | Invariant is per-object authorization (BOLA) at the API layer, not endpoint role gating |
| Admin mutation is a GraphQL field with no resolver guard | [`graphql-security-resolver-authorization`](../graphql-security-resolver-authorization/SKILL.md) | Invariant is resolver-level authorization on the mutation |
| Bypass rides a method-override header or unusual verb | [`http-method-and-verb-attacks`](../http-method-and-verb-attacks/SKILL.md) | Invariant is verb-complete enforcement across the route |
| Need parent class methodology | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate privileged functions and the role each requires.** List admin routes, management mutations, and any action that changes another user's state, and record the intended role. The gap is a function whose intended role is never asserted server-side.
2. **Separate authentication from the role assertion.** Confirm that a valid session alone reaches the handler and note whether a role check, not just a login check, runs before the action executes.
3. **Provision a low-privilege principal.** Create a non-admin account and record the functions it should be denied. This principal is the lens for every probe.
4. **Capture the administrator baseline.** Invoke each privileged function as an admin across every method it supports and record the authorised outcome and state change. This is the reference.
5. **Replay as the low-privilege principal across verbs and overrides.** Call the same function with the non-admin session, then vary the method and any override header, keeping the body constant. A success on any form is the signal.
6. **Stop condition.** Halt when the low-privilege call either (a) performs the privileged action, (b) is refused with 403 across every method and override, or (c) would require altering a real third party's records to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a privileged function executing for a low-privilege principal, shown as a differential against the admin baseline, plus the handler or route configuration that enforces the role in the UI or on one verb only. A hidden link that still refuses the action is not proof.
8. **Close with the structural fix.** Enforce the required role on the endpoint for every method with a centralised default-deny check, not in the UI, and reject method-override smuggling. Verify by replaying the low-privilege call across all verbs against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A low-privilege session receiving 200 on `/api/admin/*` | Proves the admin function lacks a server-side role gate, the core BFLA condition |
| `PUT` or `DELETE` allowed where only `GET` was exposed in the UI | Proves verb-incomplete authorization on the endpoint |
| An `X-HTTP-Method-Override` or `_method` parameter reaching a gated action | Proves method-override smuggling past a verb-scoped check |
| A role header or claim consulted instead of a server-side role lookup | Proves trust in a caller-supplied role on the stack |
| An admin GraphQL mutation executing with no resolver authorization | Proves a function-level gap at the GraphQL resolver |
| A privileged route outside the role's baseline suddenly returning success | Proves reachability of functions beyond the role's intended set |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.route("/api/admin/users", methods=["GET", "POST", "DELETE"])
@login_required
def admin_users():
    # Authentication only; the role check lives in the UI, not here
    if request.method == "GET":
        return jsonify(list_users())
    if request.method == "POST":
        return jsonify(create_user(request.get_json()))
    return jsonify(delete_user(request.args.get("id")))
```

**Hardened pattern:**

```python
import functools


def require_role(role):
    def wrapper(fn):
        @functools.wraps(fn)
        def inner(*args, **kwargs):
            if not current_user.has_role(role):
                abort(403)
            return fn(*args, **kwargs)
        return inner
    return wrapper


@app.route("/api/admin/users", methods=["GET", "POST", "DELETE"])
@login_required
@require_role("admin")  # enforced for every method, not just the UI
def admin_users():
    if request.method == "GET":
        return jsonify(list_users())
    if request.method == "POST":
        return jsonify(create_user(request.get_json()))
    return jsonify(delete_user(request.args.get("id")))
```

**Why this matters:** The defect proves who the caller is but never checks the privilege the action requires, so any authenticated user reaches the admin verbs. The control asserts the required role on every method of the endpoint server-side, so hiding the link or gating one verb is no longer what protects the function.

## When It Is NOT This Issue

- **Role enforced, link hidden:** a route whose handler refuses non-admin callers is protected even if the UI merely hides the link; test the action, not the menu.
- **Verb not routed:** a PUT or DELETE that returns 405 because the framework never dispatches it is not an incomplete gate.
- **Admin-only account used:** invoking the function with an admin session proves nothing about a low-privilege user; the differential needs the non-admin principal.
- **Self-service action misread as privileged:** a function every authenticated user is intended to call is not BFLA merely because it is powerful.
- **Override header stripped:** a stack that ignores X-HTTP-Method-Override has the control in place for that vector.
- **Batch indexes aligned:** item i is both authorized and executed by handler i. A well-formed batch is not route confusion.
- **Downstream service re-checks role:** a handler that forwards to a service which then enforces the role has a compensating control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authorization-and-idor-function-level` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authorization-and-idor-function-level` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authorization-and-idor-function-level
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-285, CWE-862 | Mapping: T1562]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-access-control-review`](../../../blue-team/application-security/secure-code-review-access-control-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`authorization-and-idor`](../authorization-and-idor/SKILL.md) - Web and Application (flagship)
- [`authorization-and-idor-object-level`](../authorization-and-idor-object-level/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-tenant-isolation`](../authorization-and-idor-tenant-isolation/SKILL.md) - Web and Application (leaf)
- [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authorization-and-idor-function-level` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-285, CWE-862, T1562`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (2), CYBER_CPT/osv (2), CYBER_CPT/gh_advisories (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
