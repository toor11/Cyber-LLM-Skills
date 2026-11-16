---
name: cors-misconfiguration-reflected-origin
description: CORS reflected and null origin abuse. Covers reflected Origin acceptance, null origin trust, and prefix or suffix matching flaws that permit attacker origins. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cors reflected origin", "null origin cors", "acao bypass"]
cwe: [CWE-942]
owasp: [A05:2021]
attack: []
capec: [CAPEC-51]
related: [cors-misconfiguration, cors-misconfiguration-credentialed-wildcard, sql-injection, cross-site-scripting]
parent: cors-misconfiguration
---

# CORS Misconfiguration Reflected Origin - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant is the origin-matching flaw itself: the server computes Access-Control-Allow-Origin by reflecting the inbound Origin after a weak check, or by trusting the literal null origin. The weak check is usually a substring, prefix, or suffix test, so an attacker crafts an Origin that passes the string match yet points at a host they control, for example target.example.attacker.test for an endsWith test or evil-target.example for a startsWith test. The security decision is the comparison logic, not the presence of CORS. The attacker gains a trusted allow-origin for a host they own and, when credentials are permitted, reads the authenticated response. Confirmation is a set of lookalike Origin values whose acceptance reveals exactly which matching mistake the code makes.

- **Precondition chain:** The server derives Access-Control-Allow-Origin from the request Origin through a substring, prefix, suffix, or null test rather than an exact set, an attacker can mint an Origin string that passes that test, credentials or sensitive data ride the response, and a victim browser attaches its cookie.
- **Readable differential:** A legitimate Origin versus a lookalike Origin engineered to pass the specific weak match; a finding exists when the lookalike is reflected into Access-Control-Allow-Origin, and it disappears once the comparison becomes an exact match against a closed origin set.
- **Empirical grounding:** CWE-942 permissive cross-domain policy under OWASP Top 10:2025 A02 Security Misconfiguration; CVE-2025-50579 (Nginx Proxy Manager) shows a reflected-origin CORS flaw leaking JWT tokens to a cross-origin reader, the reflection mechanism this variant isolates.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be origin reflection or null trust **THEN** start at the parent class [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) first
2. **IF** the trust is a wildcard or whole-subdomain-tree rule paired with credentials **THEN** switch to [`cors-misconfiguration-credentialed-wildcard`](../cors-misconfiguration-credentialed-wildcard/SKILL.md) (1 hop)
3. **IF** an allowlisted origin is itself a takeoverable host **THEN** confirm DNS ownership and read [`subdomain-takeover`](../subdomain-takeover/SKILL.md)
4. **IF** the reflected read is used to lift a CSRF token and then forge a request **THEN** chain into request forgery and read [`csrf`](../csrf/SKILL.md)
5. **IF** the Origin is null because content runs in a sandboxed iframe **THEN** test null-origin trust specifically before assuming a reflected string match
6. **IF** the reflected value is served from a cache keyed without Origin **THEN** check cache keying and read [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** every lookalike Origin is rejected and only exact allowlisted origins return the header **THEN** STOP and record a verified non-finding for this variant

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Trust is a wildcard or subdomain tree with credentials | [`cors-misconfiguration-credentialed-wildcard`](../cors-misconfiguration-credentialed-wildcard/SKILL.md) | Routes to the credential-exposure breadth rather than the match logic |
| An allowlisted origin is takeoverable | [`subdomain-takeover`](../subdomain-takeover/SKILL.md) | Invariant is DNS ownership, not the comparison code |
| Read access is used to steal a CSRF token | [`csrf`](../csrf/SKILL.md) | Invariant becomes request-origin proof after token theft |
| Need parent class methodology | [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the comparison code.** Determine whether the Origin is checked with equals, startsWith, endsWith, includes, or a regex, and whether null is special-cased; the exact operator defines the bypass string.
2. **Confirm credentials or sensitivity.** Establish that the reflected response either sends credentials true or returns data the requester could not otherwise read, so reflection has an impact.
3. **Choose the lookalike-acceptance oracle.** The oracle is which crafted Origin strings are echoed back; each string is designed to pass one specific operator, so acceptance names the mistake with no data read.
4. **Record a legitimate-Origin baseline.** Send a real allowlisted Origin and capture the header so the intended reflection is known.
5. **Apply the matched-set differential.** Send a suffix-attack Origin, a prefix-attack Origin, an embedded-domain Origin, and null; compare which are reflected to pinpoint the operator from evidence.
6. **Stop condition.** Halt when the probe either (a) reflects a lookalike or null Origin and reverts under exact matching, (b) reflects only genuinely allowlisted origins, or (c) would require reading another user's live data to show impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a specific crafted Origin that the attacker controls being echoed into Access-Control-Allow-Origin, reproducible from one changed header, plus the matching operator it defeats and the response sensitivity. A rejected lookalike is not proof.
8. **Close with the structural fix and verify.** Replace substring, prefix, suffix, and regex checks with exact membership in a closed origin set, drop null trust unless a feature demands it, then replay every lookalike Origin and confirm all are rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An `endsWith(".example.com")` Origin check reflecting the value | Proves a suffix match that target.example.com.attacker.test defeats on any stack using endsWith |
| A `startsWith("https://target.example")` Origin check | Proves a prefix match that https://target.example.attacker.test slips through |
| An `Origin.includes("target.example")` substring check | Proves a substring match that embeds the trusted token inside an attacker domain |
| Access-Control-Allow-Origin: null returned for Origin: null | Proves null trust that a sandboxed iframe or data: document can supply |
| A regex missing anchors or dot-escaping on the Origin | Proves an unanchored pattern where attacker-targetXexample matches the intended domain |
| The crafted attacker Origin echoed verbatim with credentials true | Proves the match flaw yields a credentialed read for a host the attacker controls |

## Worked Contrast

**Vulnerable pattern:**

```python
def cors_origin(origin):
    # endsWith lets target.example.com.attacker.test and null slip through
    if origin and origin.endswith("example.com"):
        return origin  # reflected verbatim
    if origin == "null":
        return "null"
    return None
```

**Hardened pattern:**

```python
ALLOWED_ORIGINS = {"https://shop.example.com", "https://id.example.com"}

def cors_origin(origin):
    # exact membership only; arbitrary subdomains and null are rejected
    return origin if origin in ALLOWED_ORIGINS else None
```

**Why this matters:** The vulnerable function reflects any Origin that ends with the trusted string and even trusts null, so a lookalike host the attacker owns is echoed back. The fix compares the Origin for exact membership in a closed set, so no suffix, prefix, substring, or null trick produces a reflected allow-origin.

## When It Is NOT This Issue

- **Exact-match comparison already used:** an equals check against a closed set cannot be defeated by lookalike strings.
- **Reflection without credentials or sensitive data:** echoing an Origin on a public response leaves nothing authenticated to read.
- **Null trust required by a legitimate feature:** a sandboxed first-party widget that must send null is acceptable when the response carries no credentials.
- **Lookalike rejected:** a crafted suffix or prefix Origin that the server refuses shows the match is anchored and safe.
- **Punycode or IDN confusion handled:** a server that normalises and rejects homoglyph origins is not reflecting an attacker host.
- **Server-to-server caller:** a non-browser client ignores the reflected header, so there is no victim to read the response.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cors-misconfiguration-reflected-origin` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cors-misconfiguration-reflected-origin` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cors-misconfiguration-reflected-origin
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-942 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cors-misconfiguration`](../cors-misconfiguration/SKILL.md) - Web and Application (leaf)
- [`cors-misconfiguration-credentialed-wildcard`](../cors-misconfiguration-credentialed-wildcard/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cors-misconfiguration-reflected-origin` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-942`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/gh_advisories (2), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
