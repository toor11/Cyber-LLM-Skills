---
name: cors-misconfiguration-credentialed-wildcard
description: CORS credentialed and wildcard flaws. Covers wildcard with credentials, insecure subdomain trust, and pre-flight and caching interactions that widen exposure. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cors credentials", "wildcard cors", "subdomain cors trust"]
cwe: [CWE-942]
owasp: [A05:2021]
attack: []
capec: [CAPEC-51]
related: [cors-misconfiguration, cors-misconfiguration-reflected-origin, sql-injection, cross-site-scripting]
parent: cors-misconfiguration
---

# CORS Misconfiguration Credentialed Wildcard - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant is the dangerous pairing of a broad allow-origin with credentialed access: either a literal wildcard combined with Access-Control-Allow-Credentials true, or a subdomain-trust rule that treats every *.example host as allowed while also sending credentials. Browsers reject the literal `*` plus credentials combination, so the real-world bug is almost always a server that dynamically echoes any subdomain, including an attacker-registered or takeoverable one, and then sets credentials true. The decision point is the origin-matching rule that widens trust to a whole domain tree rather than a closed set. The attacker gains credentialed read access from any sibling host they can obtain, so confirmation focuses on whether an arbitrary subdomain is accepted alongside credentials.

- **Precondition chain:** The server grants Access-Control-Allow-Credentials true, its origin rule trusts a whole domain tree or a wildcard rather than a closed set, an attacker can obtain or takeover a host inside that tree, and the credentialed response carries per-user data.
- **Readable differential:** A request with a legitimate subdomain Origin versus one with an attacker-controlled subdomain of the same parent; a finding exists when both are accepted with credentials true, and it ends once the rule matches only an exact allowlisted set of fully qualified origins.
- **Empirical grounding:** CWE-942 permissive cross-domain policy under OWASP Top 10:2025 A02 Security Misconfiguration describes the wildcard-with-credentials class; SOURCES has no advisory specific to credentialed subdomain trust, so grounding stays at the CWE and the browser rule that wildcard and credentials cannot legitimately combine.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be wildcard or subdomain trust with credentials **THEN** start at the parent class [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) first
2. **IF** the server reflects the exact request Origin rather than a subdomain pattern **THEN** switch to [`cors-misconfiguration-reflected-origin`](../cors-misconfiguration-reflected-origin/SKILL.md) (1 hop)
3. **IF** the trusted subdomain itself is dangling or takeoverable **THEN** confirm DNS ownership and read [`subdomain-takeover`](../subdomain-takeover/SKILL.md)
4. **IF** the leaked response body contains bearer JWTs or API keys **THEN** treat the tokens as the payoff and read [`jwt-attacks`](../jwt-attacks/SKILL.md)
5. **IF** the wildcard is set but no credentials are ever sent **THEN** downgrade severity because the browser blocks credentialed reads under a literal wildcard
6. **IF** the broad trust is on a WebSocket upgrade rather than a fetch **THEN** reclassify as handshake Origin validation and read [`websocket-security`](../websocket-security/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no arbitrary subdomain is accepted and credentials are never combined with a wildcard **THEN** STOP and record a verified non-finding for this variant

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Origin is reflected verbatim from the request | [`cors-misconfiguration-reflected-origin`](../cors-misconfiguration-reflected-origin/SKILL.md) | Routes to the string-match flaw rather than domain-tree trust |
| Trusted subdomain is itself takeoverable | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | Invariant is DNS ownership of the trusted name |
| Leaked body carries bearer tokens | [`jwt-attacks`](../jwt-attacks/SKILL.md) | Invariant is token validation once the response is exfiltrated |
| Need parent class methodology | [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the origin-matching rule.** Determine whether trust is a literal wildcard, a regex on the parent domain, or an endsWith on the apex, and whether Access-Control-Allow-Credentials true accompanies it.
2. **Establish whether credentials are in play.** A wildcard with no credentials limits impact; confirm the session cookie or auth header is attached to the cross-origin fetch before treating the breadth as a finding.
3. **Pick the subdomain-acceptance oracle.** The oracle is simply whether an arbitrary sibling subdomain is echoed into Access-Control-Allow-Origin with credentials true, which reveals the breadth of the rule with no data read.
4. **Record a legitimate-subdomain baseline.** Send a real sibling Origin and capture the allow headers to see the intended trust.
5. **Apply the arbitrary-subdomain differential.** Resend with an attacker-style subdomain of the same parent and compare; acceptance with credentials true proves the rule trusts the whole tree.
6. **Stop condition.** Halt when the probe either (a) accepts an arbitrary subdomain with credentials true and reverts under an exact-FQDN allowlist, (b) accepts only the real sibling and rejects the arbitrary one, or (c) would require registering or taking over a real host to read live data. Case (a) confirms, (b) is a non-finding, (c) is out of scope here.
7. **State what counts as proof.** Proof is an arbitrary subdomain of the trusted parent echoed into Access-Control-Allow-Origin with credentials true, reproducible from one changed Origin, plus evidence the body is per-user. A literal wildcard with no credentials is not proof.
8. **Close with the structural fix and verify.** Replace the domain-tree rule with an exact set of fully qualified origins, never combine credentials with a wildcard, add Vary: Origin, then replay the arbitrary-subdomain probe and confirm it is no longer accepted.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An origin regex like `/\.example\.com$/` matched against the request Origin | Proves domain-tree trust on any framework where a suffix regex gates credentialed CORS |
| Access-Control-Allow-Origin: * returned together with credentials true | Proves an illegal combination the browser blocks, signalling a dynamic echo bug underneath |
| An arbitrary `attacker.target.example` Origin echoed with credentials true | Proves the server trusts any sibling host, making a registerable or takeoverable subdomain sufficient |
| A shared parent domain used across tenants with credentialed CORS | Proves cross-tenant read exposure where one tenant subdomain can read another's authenticated data |
| Credentialed CORS pointing at a CNAME with no live backend | Proves a dangling trusted origin that a cloud-resource takeover could claim |
| Session cookie attached to a cross-origin fetch accepted by the subdomain rule | Proves the credentialed read is reachable, completing the wildcard-with-credentials finding |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin", "")
    # trusts every subdomain of the parent and sends credentials
    if origin.endswith(".example.com"):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp
```

**Hardened pattern:**

```python
ALLOWED = {"https://app.example.com", "https://portal.example.com"}

@app.after_request
def add_cors(resp):
    origin = request.headers.get("Origin", "")
    # exact fully qualified origins only; credentials never ride a wildcard
    if origin in ALLOWED:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp
```

**Why this matters:** The vulnerable handler trusts any host ending in the parent domain and sends credentials, so an attacker-registered subdomain reads authenticated data. The fix matches only an exact set of fully qualified origins, so no sibling host the attacker can obtain is ever reflected, and it adds Vary: Origin for cache correctness.

## When It Is NOT This Issue

- **Literal wildcard with no credentials:** Access-Control-Allow-Origin: * without credentials true cannot carry a cookie, so no authenticated read occurs.
- **Exact FQDN allowlist:** a closed set of fully qualified origins does not trust arbitrary subdomains even though multiple hosts are allowed.
- **Subdomain is first-party and non-registerable:** a parent-domain rule is only a finding if an attacker can obtain or takeover a matching host.
- **Credentials attached but body is public:** a credentialed response that contains no per-user data leaks nothing of value.
- **Preflight blocks the method:** an OPTIONS preflight rejected for the attacker subdomain stops the credentialed read.
- **Internal-only parent domain:** a rule over a domain tree reachable only inside the corporate network has no external attacker origin.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cors-misconfiguration-credentialed-wildcard` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cors-misconfiguration-credentialed-wildcard` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cors-misconfiguration-credentialed-wildcard
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-942 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) - Web and Application (leaf)
- [`cors-misconfiguration-reflected-origin`](../cors-misconfiguration-reflected-origin/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cors-misconfiguration-credentialed-wildcard` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-942`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 13 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (10), OffsecCyber (1), bug-bounty-pentest-en (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
