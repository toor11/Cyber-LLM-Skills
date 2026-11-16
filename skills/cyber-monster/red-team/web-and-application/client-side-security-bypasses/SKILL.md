---
name: client-side-security-bypasses
description: "Bypasses client-side controls: JavaScript validation, disabled inputs and hidden fields, client-side authorization and routing guards, localStorage trust, and API calls made directly past the UI. Use when a control appears to exist only in the browser."
family: web-and-application
tier: core
triggers: ["client side bypass", "javascript validation bypass", "hidden field tampering", "frontend bypass", "dom bypass"]
cwe: [CWE-602]
owasp: [A04:2021]
attack: []
capec: [CAPEC-31]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Client Side Security Bypasses - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

These flaws exist when a control that decides access, validity, or pricing runs only in the browser and the server simply trusts whatever the client ultimately sends. The browser's disabled attributes, hidden fields, JavaScript validators, and route guards are convenience, not enforcement; an attacker who talks to the API directly, edits the DOM, or replays a request never executes that code. The security decision must be re-made server-side, and the flaw is that it is not. The attacker submits the value the UI forbade (a disabled price, a hidden role, a blocked quantity) or calls an endpoint the client-side router hid, and the server accepts it. Confirmation is the server performing a privileged or invalid action in response to a request the UI would never allow.

- **Precondition chain:** A validation, authorization, or pricing decision is implemented in client-side code only, the corresponding endpoint accepts the raw value without re-deciding, and submitting the UI-forbidden value produces a privileged or invalid server-side effect.
- **Readable differential:** The request the UI produces versus the same request sent directly with a UI-forbidden value; a finding exists when the direct request succeeds server-side and it closes once the server re-validates and re-authorizes independently of the client.
- **Empirical grounding:** CWE-602 Client-Side Enforcement of Server-Side Security, an OWASP Top 10:2025 A06:2025 Insecure Design concern. SOURCES.md lists no bypass-specific advisory for this class, so the grounding stays at the CWE-602 taxonomy level rather than naming a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a disabled input, hidden field, or JavaScript validator is the only thing blocking a value **THEN** send the value directly to the endpoint and re-check server-side acceptance
2. **IF** a client-side router or guard hides a page or action rather than the server denying it **THEN** call the underlying endpoint directly; the fix is server-side authorization
3. **IF** the tampered field is actually an object identifier granting another principal's data **THEN** reclassify as access control and read [`authorization-and-idor`](../authorization-and-idor/SKILL.md)
4. **IF** the server binds extra hidden fields such as role or price from the body **THEN** model it as mass assignment and read [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md)
5. **IF** a client-side value feeds a sink that pollutes object prototypes **THEN** route to [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md)
6. **IF** the bypass only changes what the user sees, not what the server stores or authorizes **THEN** confirm a server-side effect before claiming a finding
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the server independently re-validates and re-authorizes every UI-forbidden value **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The tampered field selects another principal's object | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Invariant is per-object authorization, decided server-side |
| Hidden or disabled fields are bound into the model on write | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Invariant is which fields are server-writable |
| A client value reaches a prototype-mutating sink | [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) | Invariant is object-prototype integrity, a different sink |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Separate client-side decisions from server-side ones.** Inventory every validator, disabled control, hidden field, and route guard in the front end, and for each ask whether an equivalent check exists on the endpoint it feeds. The ones with no server equivalent are the sinks.
2. **Classify the client control.** Input validation (format, range), authorization (route or feature guard), value fixing (disabled or hidden field), or flow gating (a wizard that hides a step). Each is bypassed the same way but proves a different impact.
3. **Capture the honest request the UI makes.** With the browser behaving normally, record the exact request for the action, including the fields the UI fills and the ones it keeps read-only.
4. **Resend the request with the UI-forbidden value.** Outside the browser, submit the disabled or hidden value, the out-of-range input, or the guarded endpoint path, keeping everything else identical.
5. **Read the server-side effect, not the screen.** Confirm whether the server stored the value, authorized the action, or returned data the UI would have hidden. A client that re-renders is irrelevant if the server rejected the write.
6. **Stop condition.** Stop when the direct request either (a) produces a privileged or invalid server-side effect that reverts once the server re-validates, (b) is rejected by a server-side check identical to the client one, or (c) would alter another real user's data to demonstrate. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the server accepting a value or action the UI forbade, evidenced by the persisted field or the returned privileged response, plus the absence of a server-side re-check. A DOM edit that only changes local rendering is not proof.
8. **Close with the structural fix and verify.** Re-implement every security-relevant validation and authorization on the server, treat the client control as UX only, then replay the direct UI-forbidden request to confirm the server now refuses it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An endpoint accepting a value the form marks `disabled` or `readonly` | Proves the fixing of that field is client-only on the write path |
| A page or action reachable by URL that the client router hides | Proves authorization is enforced in the front-end guard, not the server |
| A hidden input (role, tier, price) echoed back and accepted on submit | Proves a UI-fixed field is server-writable, a client-trust gap |
| Out-of-range input blocked by a JS validator but stored when posted directly | Proves range validation exists only in the browser |
| A feature flag read from client state to gate a privileged call | Proves the entitlement check runs client-side rather than per-request on the server |
| An API returning records the SPA filters out before display | Proves server-side filtering is absent and the client enforces visibility |
| A multi-step wizard whose skipped step is not re-validated on submit | Proves flow gating is client-only on that endpoint |

## Worked Contrast

**Vulnerable pattern:**

```python
def update_profile(req, session_user, db):
    # Trusts client fields the UI marks read-only (role, tier)
    db.update_user(session_user.id, {
        'display_name': req.form['display_name'],
        'role': req.form.get('role', 'user'),
        'tier': req.form.get('tier', 'free'),
    })
    return {'ok': True}
```

**Hardened pattern:**

```python
EDITABLE = {'display_name'}

def update_profile(req, session_user, db):
    # Server decides which fields are writable; role and tier are never client-set
    changes = {k: req.form[k] for k in EDITABLE if k in req.form}
    db.update_user(session_user.id, changes)
    return {'ok': True}
```

**Why this matters:** The defective handler writes role and tier from the request because the UI only disabled them client-side; the fixed handler enforces a server-side allowlist of editable fields, so a disabled control in the browser is backed by a real server decision.

## When It Is NOT This Issue

- **Server re-validates identically:** if the endpoint rejects the UI-forbidden value just as the client did, the duplicated client check is UX, not a flaw.
- **Render-only change:** editing the DOM to reveal a field or button with no accepted server write affects only your own screen.
- **Guarded endpoint still authorizes server-side:** a hidden route the server independently denies by role is not bypassable.
- **Self-scoped data:** reading or changing only your own records through a direct call is not a cross-boundary finding.
- **Public data the UI merely declutters:** records the client hides for tidiness but that are not sensitive carry no impact when fetched directly.
- **Validation duplicated for latency only:** a client check that mirrors an enforced server rule is intended defence-in-depth.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `client-side-security-bypasses` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `client-side-security-bypasses` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: client-side-security-bypasses
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-602 | Mapping: A04:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `client-side-security-bypasses` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-602`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (3), CYBER_CPT/ctftime (2), CYBER_CPT/go_exploitdb (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
