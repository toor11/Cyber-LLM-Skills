---
name: oauth-oidc-misconfiguration-redirect-uri-abuse
description: OAuth redirect URI validation bypass. Covers path traversal, subdomain and wildcard, open redirect chaining, and parser differentials that leak authorization codes or tokens. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["oauth redirect_uri", "redirect uri bypass", "authorization code leak", "oauth redirect"]
cwe: [CWE-601, CWE-287]
owasp: [A07:2021]
attack: [T1550]
capec: [CAPEC-657]
related: [oauth-oidc-misconfiguration, oauth-oidc-misconfiguration-flow-and-state-flaws, oauth-oidc-misconfiguration-token-and-scope-abuse, sql-injection]
parent: oauth-oidc-misconfiguration
---

# Oauth OIDC Misconfiguration Redirect Uri Abuse - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

The redirect_uri is where the authorization server sends the code or token, so its validation is the single most load-bearing check in the flow. The abuse is any matching weakness that lets an attacker receive the credential at a destination they control: prefix or suffix matching instead of exact match, a permitted wildcard or subdomain, path traversal within an allowed origin, a parser differential between how the server validates and how a browser resolves the URL, or an open redirector on an allowed host that bounces the code onward. Because the code is bound to redirect_uri, capturing it there, or chaining through a trusted open redirect, yields the victim's authorization code and then their session. Confirmation is an authorization request whose tampered redirect still receives the code, reverting when the server enforces exact, registered-URI matching.

- **Precondition chain:** The authorization server matches redirect_uri loosely by prefix, wildcard, traversal, or parser differential, an attacker can register or reach a destination that satisfies the loose rule, and the issued code or token lands where the attacker can read it.
- **Readable differential:** An authorization request with the exact registered redirect versus one with an appended path, sibling subdomain, or encoded traversal; a finding exists when the tampered redirect still receives the code, and it closes under exact-match validation.
- **Empirical grounding:** CWE-601 and CWE-287; RFC 9700 (BCP 240, January 2025) mandates exact redirect URI string matching and bans open redirectors in the flow.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match the redirect case **THEN** start at parent class [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) (1 hop)
2. **IF** the matching weakness is a trusted open redirector on an allowed host **THEN** chain through [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) (1 hop)
3. **IF** the bypass is an encoded ../ traversal inside the allowed path **THEN** treat it as a path-normalisation differential and keep the probe non-destructive
4. **IF** a wildcard or sibling subdomain is accepted **THEN** enumerate the registered pattern and confirm which host variants satisfy it
5. **IF** the server and the browser parse the URL differently via @, #, or backslash **THEN** test a parser differential where validation and resolution disagree
6. **IF** the leaked credential is a token in the fragment rather than a code **THEN** note implicit-flow fragment leakage and route token handling to [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) (1 hop)
7. **IF** the redirect is a generic app open redirect unrelated to OAuth **THEN** pivot to [`open-redirect`](../open-redirect/SKILL.md) for the standalone case
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)
9. **IF** only the exactly registered redirect URI receives the code and no allowed-host open redirector exists **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| An allowed host carries an open redirector | [`open-redirect-chain-to-token-theft`](../open-redirect-chain-to-token-theft/SKILL.md) | Invariant is the onward redirect that forwards the code, not the match itself |
| The leaked credential is a fragment token | [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) | Invariant shifts to token handling once the token is captured |
| A standalone open redirect outside OAuth | [`open-redirect-allowlist-bypass`](../open-redirect-allowlist-bypass/SKILL.md) | Invariant is redirect allowlisting without the authorization-code context |
| Need parent class methodology | [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Recover the registered redirect_uri and the matching rule.** Read the client registration or infer it, and determine whether the server appears to match exactly, by prefix, by host, or with a wildcard.
2. **Classify the candidate bypass.** Appended path, sibling or wildcard subdomain, encoded traversal within the path, parser differential (@, backslash, #, or double-encoding), or an open redirector on the allowed host; each tests a different flaw in the same check.
3. **Record a clean baseline.** Issue an authorization request with the exact registered redirect and confirm where the code is delivered.
4. **Change only the redirect and observe delivery.** Submit one tampered redirect at a time and watch whether the authorization server still issues a code and to which host it sends it.
5. **For allowed-host redirectors, test the onward hop.** If an allowed host 302s to an external target, confirm the code or fragment is forwarded, because that is how an exact-match server can still leak.
6. **Stop condition.** Halt when a tampered redirect either (a) receives the code at an attacker-reachable destination and reverts under exact matching, (b) is rejected identically to a foreign URI, or (c) would require intercepting a real user's code. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an authorization code or token delivered to a destination other than the exactly registered URI as a result of one redirect change, plus the loose-matching rule or open redirector that allowed it. A redirect to the registered URI is not proof.
8. **Distinguish match failure from onward-redirect failure.** A server that matches loosely and a server that matches exactly but trusts an open redirector are two different root causes; name which one applies.
9. **Close with the structural fix.** Enforce exact, case-sensitive, fully-qualified redirect URI matching against the registration, forbid wildcards and traversal, and remove or isolate open redirectors on registered hosts, then replay the tampered redirects to confirm the code is withheld.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An authorization request with an appended path on the registered host still issued a code | Proves prefix rather than exact redirect matching at the authorization server |
| A sibling or wildcard subdomain accepted as the redirect | Proves host-pattern matching that an attacker-registered subdomain can satisfy |
| An encoded %2e%2e%2f traversal inside the allowed path accepted | Proves a normalisation differential between validation and the final location |
| A redirect using @, backslash, or double-encoding parsed differently by server and browser | Proves a parser differential where validation and resolution disagree |
| An allowed host that 302s the code to an external target | Proves an open-redirector chain that leaks the code despite exact matching |
| A token delivered in the URL fragment to a tampered host | Proves implicit-flow fragment leakage through the redirect weakness |
| Case or trailing-slash variants of the registered URI accepted | Proves non-exact string comparison in the matcher |

## Worked Contrast

**Vulnerable pattern:**

```python
def validate_redirect(supplied, registered):
    # Prefix match: any path or subpath under the registered URI passes
    if supplied.startswith(registered):
        return True
    # Also tolerates an extra query or fragment on the same host
    return supplied.split("?")[0].startswith(registered)
```

**Hardened pattern:**

```python
REGISTERED = {"https://app.example/oauth/callback"}

def validate_redirect(supplied):
    # Exact, case-sensitive, full-string match against the registered set;
    # no prefix, wildcard, traversal, or added query is accepted (RFC 9700)
    return supplied in REGISTERED
```

**Why this matters:** The defect accepts any URI that begins with the registered string, so a traversal suffix or a lookalike subdomain passes and the code is delivered to the attacker. Exact full-string matching against the registered set is the structural control, and open redirectors on the registered host must also be removed.

## When It Is NOT This Issue

- **Registered URI used:** delivery of the code to the exactly registered redirect_uri is the flow working, not a leak.
- **Open redirect on an unrelated host:** a redirector that is not a registered OAuth host cannot receive the code and is a separate standalone issue.
- **Traversal that normalises back inside:** an encoded ../ that resolves to a path still under the registered URI does not reach an attacker destination.
- **Rejected sibling domain:** a server that refuses a lookalike subdomain is matching on the registered origin correctly.
- **Fragment stays on the registered host:** an implicit-flow token delivered to the registered host is not leaked until the host forwards it.
- **Dev wildcard:** a localhost or wildcard redirect in a test IdP is an artefact unless the production registration allows it.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `oauth-oidc-misconfiguration-redirect-uri-abuse` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `oauth-oidc-misconfiguration-redirect-uri-abuse` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: oauth-oidc-misconfiguration-redirect-uri-abuse
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-601, CWE-287 | Mapping: T1550]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`oauth-oidc-misconfiguration`](../oauth-oidc-misconfiguration/SKILL.md) - Web and Application (core)
- [`oauth-oidc-misconfiguration-flow-and-state-flaws`](../oauth-oidc-misconfiguration-flow-and-state-flaws/SKILL.md) - Web and Application (leaf)
- [`oauth-oidc-misconfiguration-token-and-scope-abuse`](../oauth-oidc-misconfiguration-token-and-scope-abuse/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `oauth-oidc-misconfiguration-redirect-uri-abuse` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-601, CWE-287, T1550`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 61 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (32), hackerone_disclosed_reports (12), SecEval/cwe (8), CYBER_CPT/nuclei_templates (8) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 9 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
