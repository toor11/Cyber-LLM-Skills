---
name: oauth-oidc-misconfiguration-flow-and-state-flaws
description: OAuth flow and state parameter flaws. Covers missing or unvalidated state, PKCE downgrade, implicit flow token leakage, and mix-up attacks between providers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["oauth state", "pkce downgrade", "implicit flow", "oauth mixup"]
cwe: [CWE-601, CWE-287]
owasp: [A07:2021]
attack: [T1550]
capec: [CAPEC-657]
related: [oauth-oidc-misconfiguration, oauth-oidc-misconfiguration-redirect-uri-abuse, oauth-oidc-misconfiguration-token-and-scope-abuse, sql-injection]
parent: oauth-oidc-misconfiguration
---

# Oauth OIDC Misconfiguration Flow and State Flaws - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

This variant targets the parameters that bind an OAuth or OIDC flow to one browser and one session: state, nonce, and the PKCE code_challenge and code_verifier, plus the choice of response_type. If state is absent, static, or unvalidated, an attacker can forge the callback (login CSRF) or inject their own code; if nonce is not checked, an id_token can be replayed; if the authorization server accepts a code_verifier when no code_challenge was sent, PKCE is downgraded; and if two providers are configured, a mix-up can route a code issued by one to the client expecting another. The gain is session fixation, account takeover, or code and token injection without ever defeating a signature. Confirmation is a flow that completes after one of these bindings is removed or substituted, reverting when the one-time, session-bound check is enforced.

- **Precondition chain:** The flow relies on state, nonce, or PKCE to bind code and session, at least one binding is missing, static, reusable, or downgradable, and the attacker can replay or pre-seed the corresponding parameter.
- **Readable differential:** A flow with correct state, nonce, and PKCE versus one with state omitted, nonce unchecked, or the challenge stripped; a finding exists when the weakened flow still authenticates, and it closes when the binding is enforced as one-time and session-bound.
- **Empirical grounding:** CWE-287 and CWE-601; RFC 9700 (BCP 240, January 2025) requires PKCE S256, rejecting a code_verifier when no code_challenge was sent (the PKCE downgrade defence), and nonce or one-time state for CSRF.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match the flow-and-state case **THEN** start at parent class [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) (1 hop)
2. **IF** the problem is actually how the redirect_uri is matched **THEN** switch to [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) (1 hop)
3. **IF** the token itself is reused or its audience is unchecked once the flow completes **THEN** switch to [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) (1 hop)
4. **IF** state is missing or static and the callback mutates account state **THEN** treat it as login CSRF and confirm the victim ends up in the attacker's session
5. **IF** a code_verifier is accepted with no prior code_challenge **THEN** report a PKCE downgrade, because RFC 9700 requires the server to reject it
6. **IF** the id_token is consumed without a nonce check **THEN** test id_token replay against the client with a second controlled flow
7. **IF** two identity providers are configured and a code can cross between them **THEN** assess the mix-up case and keep both flows on controlled accounts
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
9. **IF** state and nonce are one-time and session-bound and PKCE S256 cannot be downgraded **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The defect is loose redirect_uri matching | [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) | Invariant is redirect destination exactness, not session binding |
| The issue is token reuse or audience validation after the flow | [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | Invariant is token audience and lifetime, not the state or nonce binding |
| The id_token signature or alg is the weak point | [`jwt-attacks-algorithm-confusion`](../jwt-attacks-algorithm-confusion/SKILL.md) | Invariant is signature integrity, not flow binding parameters |
| Need parent class methodology | [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Capture the full flow and locate the binding parameters.** Record state, nonce, code_challenge and its method, code_verifier, and response_type across the authorization request, the callback, and the token exchange.
2. **Classify each binding's strength.** Decide whether state is present, random, and one-time; whether nonce is checked against the session; and whether PKCE uses S256 and is mandatory, because the weakest binding is the finding.
3. **Record a clean baseline flow.** Complete a correct login with a controlled account and note the issued code, the id_token nonce, and the resulting session.
4. **Choose the branch from the observed weakness.** A missing or static state routes to a login-CSRF test; an unchecked nonce routes to an id_token replay test; a strippable challenge routes to a PKCE-downgrade test; configured dual providers route to a mix-up test.
5. **Weaken one binding and replay against the baseline.** Omit state, reuse a prior state, submit a code_verifier with no challenge, or replay an id_token with a stale nonce, changing a single variable each time.
6. **Stop condition.** Halt when the weakened flow either (a) still authenticates or fixes a session and reverts when the binding is enforced, (b) is rejected exactly as an invalid flow is, or (c) would require a real victim's live code or id_token. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a completed authentication after a binding was removed or substituted, evidenced by a session that belongs to the attacker's forged flow or a replayed id_token accepted twice, tied to that one change, plus the missing RFC 9700 binding. A rejected callback is not proof.
8. **Separate CSRF from replay from downgrade.** State failures are a CSRF or injection class, nonce failures are a replay class, and PKCE failures are a downgrade class; name which one broke so the fix is specific.
9. **Close with the structural fix.** Generate a random one-time state and nonce bound to the session and reject any mismatch, require PKCE S256 and reject a verifier with no matching challenge, and for multi-provider clients bind the issuer to the request, then replay the weakened flow to confirm rejection.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A callback accepted with state absent or set to a constant | Proves missing one-time binding, enabling login CSRF or code injection in the relying party |
| An id_token accepted twice with the same or no nonce | Proves replay exposure in the OIDC client regardless of signature validity |
| A token exchange that succeeds with a code_verifier but no prior code_challenge | Proves a PKCE downgrade the authorization server failed to reject |
| code_challenge_method=plain accepted where S256 is expected | Proves a weakened PKCE binding that RFC 9700 deprecates |
| A code from provider A accepted by the client's provider-B exchange | Proves an IdP mix-up where the issuer is not bound to the request |
| response_type=token returning a token in the URL fragment | Proves an implicit-flow leakage surface the client still accepts |
| A state value that is predictable or reused across users | Proves the binding is forgeable rather than merely present |

## Worked Contrast

**Vulnerable pattern:**

```python
def token_exchange(request, stored):
    code = request.form["code"]
    verifier = request.form.get("code_verifier")
    challenge = stored.get("code_challenge")
    # Downgrade bug: when no challenge was stored, PKCE is simply skipped
    if challenge and sha256_b64(verifier) != challenge:
        abort(400)
    return issue_tokens(code)
```

**Hardened pattern:**

```python
def token_exchange(request, stored):
    code = request.form["code"]
    verifier = request.form.get("code_verifier", "")
    challenge = stored.get("code_challenge")
    # RFC 9700: a challenge must have been registered and must match S256
    if not challenge:
        abort(400)
    if stored.get("method") != "S256" or sha256_b64(verifier) != challenge:
        abort(400)
    return issue_tokens(code)
```

**Why this matters:** The defect skips PKCE whenever no code_challenge was stored, so an attacker who intercepts a code can redeem it with any or no verifier, a PKCE downgrade. The fix requires a stored S256 challenge and a matching verifier for every exchange, rejecting the downgrade exactly as RFC 9700 specifies.

## When It Is NOT This Issue

- **State present and one-time:** a callback that rejects a reused or altered state is protected; absence of other hardening does not reopen it.
- **Nonce checked:** an id_token flow that compares nonce to the session resists replay even if the token is long-lived.
- **Public client, PKCE enforced:** no client secret is expected for public clients when S256 PKCE is mandatory and verified.
- **Single provider:** a mix-up test is moot when only one IdP is configured and the issuer is fixed.
- **Implicit flow disabled:** response_type=token returning an error is the server refusing the legacy grant, not a leak.
- **Dev loopback flow:** a localhost redirect accepting a relaxed flow in a test build is an artefact unless production behaves the same.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `oauth-oidc-misconfiguration-flow-and-state-flaws` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `oauth-oidc-misconfiguration-flow-and-state-flaws` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: oauth-oidc-misconfiguration-flow-and-state-flaws
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601, CWE-287 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) - Web and Application (core)
- [`oauth-oidc-misconfiguration-redirect-uri-abuse`](../oauth-oidc-misconfiguration-redirect-uri-abuse/SKILL.md) - Web and Application (leaf)
- [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `oauth-oidc-misconfiguration-flow-and-state-flaws` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601, CWE-287, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/osv (3), CYBER_CPT/gh_advisories (2), cyber-security/security-code (1), cyber-security/CyberSec-Dataset (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
