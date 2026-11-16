---
name: authentication-bypass-response-manipulation
description: Authentication bypass through response manipulation. Covers flipping server responses client-side, tampering with status codes and redirects, and exploiting trust in client-side flags. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["response manipulation auth", "status code bypass", "client trust bypass"]
cwe: [CWE-287]
owasp: [A07:2021]
attack: [T1078]
capec: [CAPEC-115]
related: [authentication-bypass, authentication-bypass-forced-browsing, authentication-bypass-default-and-weak-credentials, authentication-bypass-header-and-proxy-trust]
parent: authentication-bypass
corpus_sparse: true
---

# Authentication Bypass Response Manipulation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

This variant targets designs where the authentication or authorization decision is effectively made on the client, so manipulating the server's response flips the outcome. A thick client, single-page app, or mobile backend returns the protected payload alongside a status code or a boolean flag such as `authenticated:false`, and trusts the client to honour it; an intercepting proxy simply rewrites the 401 to 200 or the flag to true and proceeds into the authenticated view. The server-side defect is that it emitted protected state before the access decision gated it, or delegated the gate to a client-interpreted value. The attacker reaches authenticated functionality without any valid credential, and confirmation is that the protected content is present in the deny-branch response or is identical across the allowed and denied branches.

- **Precondition chain:** the server returns protected state or a privileged payload regardless of the access outcome, the real gate is a client-interpreted status or flag, and the client can be made to treat the denied response as allowed.
- **Readable differential:** the deny-branch response versus the allow-branch response for the same protected resource; a finding exists when the protected content is present in or identical to the deny branch, and it closes once the server withholds the payload until its own decision succeeds.
- **Empirical grounding:** CWE-287 Improper Authentication expressed as CWE-603 Use of Client-Side Authentication; there is no leaf-specific advisory in scope, so OWASP Top 10:2025 A07 Authentication Failures and the client-side-trust taxonomy anchor the guidance.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match response manipulation **THEN** start at parent class [`authentication-bypass`](../authentication-bypass/SKILL.md) (1 hop) for general triage
2. **IF** a 401 or 403 response still carries the protected fields in its body **THEN** treat the deny-branch leak as the primary signal before testing flags
3. **IF** the login returns a success boolean that the client acts on **THEN** test whether the privileged payload ships even when the flag is false
4. **IF** the protected body is byte-identical across the 200 and 401 branches **THEN** model it as status-only enforcement that a proxy can flip
5. **IF** the flipped value is a role or privilege flag in the response **THEN** reclassify as property trust and read [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md)
6. **IF** the bypass intercepts an OAuth or OIDC redirect or token response **THEN** route to [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md)
7. **IF** client-side JavaScript alone enforces the gate **THEN** route to [`client-side-security-bypasses`](../client-side-security-bypasses/SKILL.md) because the decision cannot live in the client
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the deny branch returns no protected state and flipping the client reveals nothing **THEN** STOP and record a verified non-finding rather than reporting a cosmetic UI change

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Flipped value is a role or privilege flag in the response | [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) | Invariant is server-authoritative privilege, not client-rendered state |
| Bypass intercepts an OAuth or OIDC redirect or token response | [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) | Invariant is server-side flow and state validation |
| Client-side code alone enforces the gate in JavaScript | [`client-side-security-bypasses`](../client-side-security-bypasses/SKILL.md) | Invariant is that security decisions cannot live in the client |
| Need parent class methodology | [`authentication-bypass`](../authentication-bypass/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Identify where the access decision is actually consumed.** Trace whether the client branches on an HTTP status, a JSON boolean, or a redirect, and whether the server emits the protected payload before or after that decision. The sink is the point where protected state is serialised.
2. **Capture both branches of the same resource.** Record the allow-branch response for a legitimate session and the deny-branch response for a missing or invalid credential, including full bodies and headers. The comparison between them is the whole test.
3. **Inspect the deny branch for protected content.** Look for populated user, dashboard, balance, or role fields inside a 401 or 403 body, or for a privileged payload accompanying an `authenticated:false` flag. Presence here is the direct signal.
4. **Test status and flag independence.** Flip the status or the boolean client-side with an intercepting proxy and observe whether the application unlocks while the underlying data was already present. This confirms the gate is client-interpreted.
5. **Separate a cosmetic change from a data exposure.** A UI that merely renders a different view without new server data is not the finding; the protected state must have crossed to the client in the deny branch.
6. **Stop condition.** Halt when the resource either (a) exposes protected state in the deny branch or is identical across branches so a flip unlocks it, (b) returns no protected content in the deny branch and differs correctly from the allow branch, or (c) would require acting on another real user's data to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is protected data obtained from the deny-branch response, or a byte-identical body across branches that a client flip unlocks, tied to the server line that emitted the payload before the decision. A re-rendered view with no new server data, or a flag flip that reveals nothing, is not proof.
8. **Close with the structural fix.** Make the protected payload contingent on the server-side decision, return an empty body with the deny status, and never let the client's interpretation of a flag or status be the gate. Verify by re-capturing the deny branch and confirming it carries no protected state.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A 401 or 403 whose body carries the same protected fields as the 200 | Proves the server emits sensitive data before the access decision gates the client |
| An `authenticated:false` JSON response that still includes a dashboard payload | Proves the client, not the server, is trusted to act on the flag |
| Byte-identical response bodies across the authorized and unauthorized branches | Proves the only difference is the status code, which an intercepting proxy can flip |
| A login flow that routes on HTTP status rather than a server-set session | Proves client-side authentication on single-page-app or mobile stacks (CWE-603) |
| A redirect to a privileged page that can be cancelled while the data persists | Proves the gate is a client navigation rather than a server check |
| A boolean success field consumed by the UI with no server enforcement behind it | Proves trust in a client-interpreted flag rather than an enforced decision |

## Worked Contrast

**Vulnerable pattern:**

```python
def login(request):
    user = authenticate(request.form["username"], request.form["password"])
    # The privileged payload ships regardless; the client decides on the flag
    return jsonify({
        "authenticated": user is not None,
        "dashboard": build_dashboard(user or system_admin()),
    })
```

**Hardened pattern:**

```python
def login(request):
    user = authenticate(request.form["username"], request.form["password"])
    if user is None:
        # Deny branch carries no protected state at all
        return jsonify({"authenticated": False}), 401
    # The payload is produced only after the server-side decision succeeds
    return jsonify({"authenticated": True, "dashboard": build_dashboard(user)})
```

**Why this matters:** The defect serialises the dashboard into every response and delegates the trust decision to a client-read flag, so an intercepting client flips authenticated to true and reads data the server already sent. The control makes the protected payload contingent on a successful server-side authentication and returns an empty deny body, so flipping the flag reveals nothing.

## When It Is NOT This Issue

- **Cosmetic view change only:** a client that renders a different screen on a flipped flag but receives no new server data has exposed nothing protected.
- **Deny branch is empty:** a 401 that returns no body and a 200 that returns the payload is correct server-side gating, not a manipulable response.
- **Status flip rejected on next call:** a UI that unlocks momentarily but whose subsequent server calls still enforce authorization is not a real bypass.
- **Local-only tampering:** editing the response in your own browser to change your own view, with no cross-user or server-state effect, is self-only.
- **Signed response the client verifies:** a payload whose integrity the client checks against a server signature cannot be silently flipped.
- **Feature flag, not an auth gate:** flipping a non-security boolean that toggles a beta feature is not an authentication decision.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `authentication-bypass-response-manipulation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `authentication-bypass-response-manipulation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: authentication-bypass-response-manipulation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`authentication-bypass`](../authentication-bypass/SKILL.md) - Web and Application (core)
- [`authentication-bypass-forced-browsing`](../authentication-bypass-forced-browsing/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-default-and-weak-credentials`](../authentication-bypass-default-and-weak-credentials/SKILL.md) - Web and Application (leaf)
- [`authentication-bypass-header-and-proxy-trust`](../authentication-bypass-header-and-proxy-trust/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `authentication-bypass-response-manipulation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
