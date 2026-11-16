---
name: open-redirect-chain-to-token-theft
description: Open redirect chaining to token theft. Covers chaining redirects with OAuth or SSO flows to steal codes and tokens, and with SSRF to reach internal destinations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["open redirect oauth", "redirect token theft", "redirect ssrf chain"]
cwe: [CWE-601]
owasp: [A01:2021]
attack: []
capec: [CAPEC-178]
related: [open-redirect, open-redirect-allowlist-bypass, sql-injection, cross-site-scripting]
parent: open-redirect
---

# Open Redirect Chain to Token Theft - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This chain abuses an open redirect that sits inside an OAuth or SSO authorization flow so that a secret in transit, usually an authorization code or access token, is delivered to an attacker origin. The authorization server validates the redirect_uri loosely (prefix or substring), or the registered callback itself forwards to an attacker-controlled next value, so the browser carries the code or token one hop too far. The decision point is the authorization server's redirect_uri matching and the callback's own forwarding logic. The attacker gains the victim's code or token, which exchanges for an account session, so impact is account takeover rather than mere phishing. Confirmation is that the sensitive value arrives at the attacker endpoint, observed in a query string, fragment, or Referer, while an exact-match registration prevents it.

- **Precondition chain:** An OAuth or SSO flow issues a code or token to a redirect_uri, that redirect_uri is validated by prefix or forwards through an open redirect, and the resulting value is observable at an attacker-controlled destination.
- **Readable differential:** The flow completing to the registered callback versus the flow completing to an attacker host reached through the redirect; a finding exists when the code or token lands off-origin, and it stops once redirect_uri matching is exact and state is single-use.
- **Empirical grounding:** CWE-601 chained into OAuth token theft; RFC 9700 (BCP 240, January 2025) requires exact redirect URI registration, one-time state, and no open redirectors to prevent authorization-code interception.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to involve a token or code leak **THEN** start at parent class [`open-redirect`](../open-redirect/SKILL.md) for general triage
2. **IF** the redirect_uri is validated by prefix and accepts an appended path **THEN** test a registered-prefix extension that forwards to an attacker host
3. **IF** the registered callback itself honours a next or return parameter **THEN** chain the in-callback open redirect so the code rides to the attacker origin
4. **IF** the secret appears in a URL query string that downstream pages can read **THEN** test for leakage through the Referer header on the next navigation
5. **IF** the flow uses the implicit `response_type=token` **THEN** assess fragment leakage because the token never reaches the server
6. **IF** the redirect_uri matching is the authorization server's own weakness **THEN** route to [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) for exact-match enforcement
7. **IF** the server itself follows the redirect to internal hosts **THEN** route to [`ssrf`](../ssrf/SKILL.md) because the impact becomes internal reachability
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** redirect_uri is exact-matched and state is single-use so no secret leaves the origin **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The redirect_uri is validated only by prefix or substring | [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | The fix is exact redirect URI matching at the authorization server |
| The follow-through redirect is issued by the server to internal hosts | [`ssrf`](../ssrf/SKILL.md) | Impact is internal reachability, not browser-side token capture |
| The leaked value is a session token held client-side | [`session-and-token-lifecycle`](../session-and-token-lifecycle/SKILL.md) | The invariant is token storage and transport, not the redirect itself |
| Need parent class methodology | [`open-redirect`](../open-redirect/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the authorization flow and the secret in transit.** Identify whether the flow returns an authorization code (query), an implicit token (fragment), or an ID token, and which redirect_uri receives it. The location of the secret decides the leak channel.
2. **Inspect redirect_uri matching at the server.** Determine whether the authorization server does exact matching or accepts a prefix, extra path, or wildcard. A prefix acceptance is the entry to the chain.
3. **Inspect the registered callback's own forwarding.** Read whether the callback honours a next, RelayState, or return parameter after receiving the code, because an in-callback open redirect leaks the secret even when server matching is exact.
4. **Record a clean-flow baseline.** Complete the flow to the legitimate callback and capture where the code or token appears and whether any downstream request carries it in a Referer. This is the value the chain must relocate.
5. **Insert the redirect one hop at a time.** Try a registered-prefix path extension, then an in-callback next pointing at an assessor host, confirming at each step whether the code or token reaches that host rather than guessing the full chain.
6. **Stop condition.** Halt when the chain either (a) delivers a usable code or token to an attacker endpoint and is prevented by exact matching plus single-use state, (b) keeps every secret on the registered origin, or (c) would require exchanging a real victim's code for a live session. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is the authorization code or token observed arriving at an assessor-controlled destination through the redirect, plus the exact matching or forwarding line that permitted the extra hop, and evidence that state was not single-use if replay was involved. A redirect that carries no secret is not proof.
8. **Close with the structural fix and verify it.** Enforce exact redirect_uri matching, remove open forwarding from the callback, bind and expire state as one-time, and prefer PKCE S256 so an intercepted code is unusable; replay the chain to confirm the secret no longer escapes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A redirect_uri accepted by prefix so `/callback/..%2fopen-redirect` passes | Proves prefix matching at the authorization server, the opening for a code-leak chain on OAuth deployments |
| A registered callback that honours a `next` or `RelayState` after receiving the code | Proves an in-callback open redirect that relocates the secret even when server matching is exact |
| The authorization code appearing in a query string on a page with external resources | Proves a Referer-leak channel for the code on browsers that forward the full URL |
| An implicit `response_type=token` returning the token in the fragment | Proves a fragment-leak surface where the token never reaches the server and client script can exfiltrate it |
| State absent or reused across two authorization attempts | Proves the one-time-state invariant is missing, enabling code injection or fixation on the flow |
| A code or token observed arriving at an assessor host | Proves the chain completes end to end on this specific authorization server and client pair |

## Worked Contrast

**Vulnerable pattern:**

```python
def authorize(registered_prefix, redirect_uri):
    # Prefix match lets an extra path or open redirector ride the authorised origin
    if redirect_uri.startswith(registered_prefix):
        return issue_code(redirect_uri)
    raise ValueError("redirect_uri not allowed")
```

**Hardened pattern:**

```python
REGISTERED = {"https://app.example/callback"}

def authorize(redirect_uri, state):
    # Exact match against registered values; state is single-use and session-bound
    if redirect_uri not in REGISTERED:
        raise ValueError("redirect_uri not allowed")
    if not consume_state(state):
        raise ValueError("state invalid or already used")
    return issue_code(redirect_uri)
```

**Why this matters:** Prefix matching admits a callback path that forwards the code onward; the fix requires the redirect_uri to equal a registered value exactly and consumes a one-time state, so there is no extra hop for the code and no replay window.

## When It Is NOT This Issue

- **Exact redirect_uri matching enforced:** the authorization server rejects any callback that is not byte-for-byte registered, so no extra hop exists.
- **Callback does no forwarding:** the registered callback consumes the code and renders a page without honouring any next or return parameter.
- **Code bound by PKCE:** an intercepted authorization code cannot be exchanged without the verifier, so a leak carries no account impact.
- **Secret in fragment never read:** an implicit token in the fragment is cleared by the callback before any external resource loads, leaving nothing to steal.
- **State single-use and bound:** a reused or foreign state is rejected, closing code-injection and fixation angles.
- **Leak lands on the same origin:** the redirect only moves the secret between the application's own pages, which is not interception.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `open-redirect-chain-to-token-theft` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `open-redirect-chain-to-token-theft` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: open-redirect-chain-to-token-theft
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601 | Mapping: A01:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`open-redirect`](../open-redirect/SKILL.md) - Web and Application (leaf)
- [`open-redirect-allowlist-bypass`](../open-redirect-allowlist-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `open-redirect-chain-to-token-theft` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (1), CYBER_CPT/nuclei_templates (1), CYBER_CPT/go_exploitdb (1), CYBER_CPT/govuln (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
