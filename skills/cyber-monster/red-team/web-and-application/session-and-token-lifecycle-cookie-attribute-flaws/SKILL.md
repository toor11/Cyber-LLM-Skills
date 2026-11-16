---
name: session-and-token-lifecycle-cookie-attribute-flaws
description: Cookie attribute and scope flaws. Covers missing HttpOnly, Secure and SameSite, over-broad domain and path scope, and cookie shadowing across subdomains. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cookie flags", "cookie scope", "samesite bypass", "cookie shadowing"]
cwe: [CWE-384, CWE-613]
owasp: [A07:2021]
attack: []
capec: [CAPEC-60]
related: [session-and-token-lifecycle, session-and-token-lifecycle-fixation-and-prediction, session-and-token-lifecycle-revocation-gaps, sql-injection]
parent: session-and-token-lifecycle
---

# Session and Token Lifecycle Cookie Attribute Flaws - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Cookie attributes decide the scope and exposure of the session cookie independently of whether the server can revoke it. A missing HttpOnly exposes the cookie to script, a missing Secure allows transmission over cleartext, and a missing or None SameSite allows cross-site sending. An over-broad Domain set to a registrable parent lets a sibling subdomain read or overwrite the cookie through tossing and shadowing, and a loose Path or an absent host-scoped prefix lets a less-trusted path set a colliding cookie. The decision point is the Set-Cookie attribute string and any cookie a subdomain can write. The attacker gains theft, cross-site forgeability, or cookie fixation through shadowing depending on which attribute is absent.

- **Precondition chain:** a session cookie is issued without one or more of Secure, HttpOnly, or SameSite, or with a Domain or Path broader than the issuing origin, and a lower-trust context such as script, a cleartext link, or a sibling subdomain can read, send, or overwrite it.
- **Readable differential:** the session cookie with tight attributes versus the cookie as actually issued; the finding is that the issued cookie lacks an attribute, shown by script access, cleartext transmission, or a cross-subdomain overwrite succeeding, and it reverts when the attribute or a host-scoped prefix is applied.
- **Empirical grounding:** CWE-384 and CWE-613 under OWASP Top 10:2025 A07:2025 Authentication Failures anchor cookie attribute and scope weaknesses that expose or widen the session cookie.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as cookie attributes **THEN** start at parent class [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) first
2. **IF** the Set-Cookie lacks HttpOnly **THEN** pair with a script-read check, since without HttpOnly a script can read the session cookie
3. **IF** the Set-Cookie lacks Secure **THEN** test whether the cookie is sent over a cleartext request to the same host
4. **IF** SameSite is None or absent **THEN** assess cross-site sending and route the forgeability impact to [`csrf`](../csrf/SKILL.md)
5. **IF** Domain is a registrable parent domain **THEN** test cookie tossing from a sibling subdomain overwriting the session
6. **IF** no host-scoped or secure-scoped cookie prefix is used **THEN** check whether a weaker path or host can shadow the cookie
7. **IF** the cookie is read and exfiltrated by injected script **THEN** that is storage and theft; see [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the cookie carries Secure, HttpOnly, SameSite, and a host-scoped prefix **THEN** STOP and classify as a verified non-finding for CWE-384 and CWE-613

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Missing HttpOnly is exploited to exfiltrate the cookie | [`client-side-storage-and-token-theft`](../client-side-storage-and-token-theft/SKILL.md) | Exfiltration via script is a theft invariant, not an attribute-setting one |
| A SameSite gap enables a cross-site state change | [`csrf`](../csrf/SKILL.md) | Forgeability is a request-authenticity invariant that SameSite only partially covers |
| An over-broad Domain exposes the cookie via a credentialed cross-origin response | [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) | Credentialed cross-origin exposure is a CORS policy invariant distinct from cookie scoping |
| Need parent class methodology | [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Capture the exact Set-Cookie for the session.** Record every attribute as issued, Secure, HttpOnly, SameSite, Domain, Path, Max-Age, and any prefix, rather than what the documentation claims.
2. **Classify each attribute's binding role.** Map which attribute governs transport, script exposure, cross-site sending, and host scope so each test targets one decision.
3. **Baseline against a tightly scoped reference.** Note what a host-only, Secure, HttpOnly, SameSite Lax cookie would allow as the comparison point.
4. **Define the baseline-versus-probe differential per attribute.** Attempt a script read for HttpOnly, a cleartext request for Secure, a cross-site send for SameSite, and a sibling-subdomain overwrite for Domain, each as one isolated test.
5. **Branch on which attribute is missing.** A missing HttpOnly routes to theft, a missing SameSite to forgeability, and a broad Domain to cookie tossing, kept separate because the remediation differs per attribute.
6. **Stop condition.** Stop when (a) one attribute test succeeds where a tightly scoped cookie would fail, (b) every test fails because the attributes are present, or (c) proving theft would require executing injected script against a real user. Case (a) confirms the attribute flaw, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single attribute's absence demonstrated concretely, script reading the cookie, the cookie on a cleartext request, a cross-site request carrying it, or a subdomain overwrite taking effect, plus the Set-Cookie line lacking that attribute. A documentation claim is not proof.
8. **Close with the structural fix.** Set Secure, HttpOnly, and SameSite, scope Domain to the exact host and Path to the application root, and adopt a host-scoped cookie prefix so no subdomain or path can shadow the cookie; verify by re-capturing Set-Cookie and re-running each attribute test.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| The document cookie interface returning the session value in the browser | Proves HttpOnly is absent so any script can read the cookie; DOM-accessible session cookies |
| The session cookie transmitted on a cleartext request to the same host | Proves Secure is absent, exposing the cookie on an unencrypted channel; mixed-scheme deployments |
| SameSite None or no SameSite on the Set-Cookie line | Proves the cookie rides cross-site requests, enabling forgery across browsers with differing defaults |
| A Domain set to a registrable parent shared with user subdomains | Proves cookie tossing and shadowing across siblings; multi-subdomain hosting |
| A session cookie name lacking a host-scoped or secure-scoped prefix | Proves a weaker path or host can set a colliding cookie; applications without prefix enforcement |
| A Path scoped broader than the authenticated application root | Proves a sibling path can read or overwrite the session; shared-origin multi-application hosts |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.after_request
def set_session(resp):
    # No HttpOnly, no Secure, SameSite None, and Domain scoped to the parent so
    # any sibling subdomain can read or overwrite the session cookie.
    resp.set_cookie("session", current_sid(),
                    domain=".example.com", samesite="None")
    return resp
```

**Hardened pattern:**

```python
@app.after_request
def set_session(resp):
    # The host-scoped prefix forbids Domain and requires Secure with Path=/, so
    # no subdomain or path can shadow it; HttpOnly keeps it out of script.
    resp.set_cookie("__Host-session", current_sid(),
                    secure=True, httponly=True, samesite="Lax", path="/")
    return resp
```

**Why this matters:** The hardened cookie uses a host-scoped prefix, which browsers only accept when Secure is set, Path is the root, and no Domain is present, so a sibling subdomain cannot toss a colliding cookie. HttpOnly removes script access and SameSite Lax withholds it from cross-site requests, binding the session to one host, transport, and navigation context.

## When It Is NOT This Issue

- **HttpOnly absent on a non-session cookie:** a CSRF-token or UI-preference cookie without HttpOnly is often intentional, so scope the finding to the authentication cookie.
- **Secure absent during localhost testing:** cookies without Secure over cleartext localhost are a development artefact, not a production exposure.
- **SameSite Lax blocking a legitimate cross-site POST:** Lax is the safer default, so its presence is the control working, not a flaw.
- **Domain intentionally shared for single sign-on:** a parent-domain cookie used deliberately for same-organisation single sign-on is by design, provided the subdomains are all trusted.
- **Prefix unsupported by a legacy client:** omitting a host-scoped prefix to support an old agent is a compatibility trade-off, reported at reduced severity.
- **Edge proxy rewrites attributes:** if a content delivery layer adds Secure or HttpOnly downstream, the origin's bare Set-Cookie is cosmetic, so verify the browser-received header.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `session-and-token-lifecycle-cookie-attribute-flaws` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `session-and-token-lifecycle-cookie-attribute-flaws` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: session-and-token-lifecycle-cookie-attribute-flaws
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-384, CWE-613 | Mapping: A07:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-fixation-and-prediction`](../session-and-token-lifecycle-fixation-and-prediction/SKILL.md) - Web and Application (leaf)
- [`session-and-token-lifecycle-revocation-gaps`](../session-and-token-lifecycle-revocation-gaps/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `session-and-token-lifecycle-cookie-attribute-flaws` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-384, CWE-613`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (3), CYBER_CPT/hacktricks (2), CYBER_CPT/gh_advisories (2), bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
