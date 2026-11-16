---
name: web-fingerprinting-and-tech-detection
description: Identifies server, framework, CMS, language and library versions from headers, cookies, error pages, static assets, favicons and behaviour. Use when you need to select version-specific exploits or narrow which skill applies.
family: web-and-application
tier: leaf
triggers: ["fingerprint", "tech detection", "whatweb", "wappalyzer", "version detection", "server header"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Web Fingerprinting and Tech Detection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Fingerprinting infers the server, framework, CMS, language, and library versions behind an application by correlating many weak signals: the `Server` and `X-Powered-By` headers, cookie names and formats, error-page wording, static-asset paths and hashes, favicon hashes, and timing or behavioural quirks. No single signal is authoritative, so the method accumulates agreeing evidence until identification is confident enough to drive a routing decision toward a version-specific technique skill. The security-relevant decision on the target side is whether the application suppresses version and technology disclosure; when it does not, it hands the assessor the exact product and version to match against advisories. The value gained is not exploitation but confident identification that narrows which downstream skill and which n-day apply. Proof is a converging set of independent signals, not a single banner that could be spoofed or proxied.

- **Precondition chain:** The target emits at least one technology-revealing signal, that signal is corroborated by one or more independent signals, and the identification is specific enough (product and version) to change which technique or advisory you pursue.
- **Readable differential:** The fingerprint inferred from headers alone versus the fingerprint corroborated by cookies, asset hashes, and error pages; a confident identification exists when independent signals agree, and a single signal that no other evidence supports is treated as unconfirmed rather than as fact.
- **Empirical grounding:** CWE-20 and CAPEC-116 frame the class; the invariant is that product and version disclosure drives which downstream skill and advisory apply, so the proof standard is identification confidence rather than exploitation. SOURCES.md has no fingerprinting-specific advisory, so this leaf stays at the taxonomy and methodology level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** identification is confident and points to a specific CMS or framework **THEN** route to [`cms-and-framework-exploitation`](../cms-and-framework-exploitation/SKILL.md) for version-specific testing
2. **IF** a product and version map to a public advisory **THEN** confirm applicability via [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md)
3. **IF** the fingerprint points to an edge appliance or VPN rather than an app **THEN** pivot to [`enterprise-appliance-and-n-day-exploitation`](../enterprise-appliance-and-n-day-exploitation/SKILL.md)
4. **IF** you still need to find unlinked surface before fingerprinting it **THEN** read [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) first
5. **IF** only a WAF or CDN can be identified, not the origin stack **THEN** read [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](../waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) for engine fingerprinting
6. **IF** the revealing signal is a secret or key in a JavaScript bundle **THEN** pivot to [`api-key-and-secret-exposure`](../api-key-and-secret-exposure/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no signal is corroborated and identification stays a guess **THEN** STOP and record the result as unconfirmed rather than asserting a product or version

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Identification points to a specific CMS or framework | [`cms-and-framework-exploitation`](../cms-and-framework-exploitation/SKILL.md) | Routes to version-specific exploitation, a different objective |
| Product and version match an advisory | [`cve-poc-research-and-triage`](../cve-poc-research-and-triage/SKILL.md) | Routes to advisory triage rather than signal collection |
| Only the fronting WAF is identifiable | [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](../waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) | Different invariant: edge engine identity, not origin stack |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Collect the passive signals first.** Record `Server`, `X-Powered-By`, `Set-Cookie` names, security headers, default error-page wording, and the HTML `generator` meta before sending anything unusual, so the baseline fingerprint is built from normal traffic.
2. **Add active but benign signals.** Request a known default asset and read its path and content hash, compute the favicon hash, and trigger a benign 404 to read the error template; each adds an independent vote.
3. **Weight each signal by spoofability.** Treat a `Server` header as low-confidence because proxies rewrite it, and an asset hash or framework-specific cookie format as higher-confidence; record the weight with the signal.
4. **Resolve the proxy question.** Determine whether a CDN or WAF sits in front, because edge headers describe the edge not the origin; separate edge identification from origin identification explicitly.
5. **Converge to a product and version.** Combine the weighted signals and state the most specific identification the evidence supports, with the version range the agreeing signals bound.
6. **Stop condition.** Halt when identification is either (a) corroborated by two or more independent signals to a specific product and version, (b) impossible because every signal is suppressed or proxied, or (c) only supported by a single spoofable banner. Outcome (a) is a confident identification to route on, (b) is a verified non-finding for disclosure, (c) must be labelled unconfirmed, not asserted.
7. **State what counts as proof.** Proof of identification is a set of independent, weighted signals that agree on one product and version, with the spoofable ones excluded from the conclusion. A lone `Server: nginx/1.2.3` with no corroboration is a lead, not a verified fingerprint.
8. **Close with the structural fix and verify it.** The target-side fix is to suppress version tokens (unset `Server` and `X-Powered-By`, remove `generator` meta, serve generic error pages, rename default assets), then re-fingerprint to confirm the product and version are no longer inferable from the remaining signals.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `Server` or `X-Powered-By` header carrying a product and version string | Proves version disclosure but is low-confidence because proxies and config can rewrite it |
| A framework-specific session cookie name (`PHPSESSID`, `JSESSIONID`, `connect.sid`) | Proves the server-side language or framework on most default deployments |
| A favicon or static-asset hash matching a known product build | Proves identification with high confidence because it is tied to shipped files |
| A default error or debug page with product-specific wording | Proves the framework and sometimes a version band from its template |
| An HTML `generator` meta tag naming a CMS and version | Proves the CMS on stock installations until the admin removes it |
| Edge headers (`cf-ray`, `x-amz-cf-id`) describing a CDN, not the origin | Proves a proxy is present, which must be separated from origin identification |
| Two independent signals agreeing on the same version band | Proves a confident identification suitable for routing to a version-specific skill |

## Worked Contrast

**Vulnerable pattern:**

```python
app = Flask(__name__)
app.config['DEBUG'] = True     # verbose stack traces reveal framework and version

@app.after_request
def add_headers(resp):
    resp.headers['Server'] = f'Werkzeug/{werkzeug.__version__} Python/{sys.version.split()[0]}'
    resp.headers['X-Powered-By'] = 'Flask'
    return resp
```

**Hardened pattern:**

```python
app = Flask(__name__)
app.config['DEBUG'] = False    # generic error pages, no stack traces

@app.after_request
def strip_version_headers(resp):
    # Remove product and version disclosure; serve a neutral Server token
    resp.headers['Server'] = 'web'
    resp.headers.pop('X-Powered-By', None)
    return resp

@app.errorhandler(Exception)
def generic_error(_e):
    return make_response('error', 500)   # no framework-specific wording
```

**Why this matters:** The defect is that the application advertised its framework and exact versions through headers and verbose error pages, handing an assessor the precise product and version to match against advisories. The fix disables debug output, replaces the `Server` token with a neutral value, drops `X-Powered-By`, and returns generic errors, so version identification can no longer converge.

## When It Is NOT This Issue

- **Spoofed or proxied banner:** a `Server` header set by a CDN or deliberately falsified describes the edge or a decoy, not the origin stack.
- **Version header without a reachable surface:** knowing the version of a component that exposes no tested functionality is informational, not a finding.
- **Stale asset from cache or archive:** an old build hash retrieved from a cache or the Wayback archive may not match the live deployment.
- **Generic defaults:** a cookie name or error page shared by many products identifies a family, not a specific version.
- **Deliberate honey-banner:** a header advertising a product the host does not actually run is a deception control, not disclosure.
- **Edge-only identification:** confidently naming the CDN while the origin stays hidden is not origin fingerprinting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-fingerprinting-and-tech-detection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-fingerprinting-and-tech-detection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-fingerprinting-and-tech-detection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-fingerprinting-and-tech-detection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 28 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/L5/ctf_search (11), CYBER_CPT/oxdf (10), OffsecCyber (4), bugbounty-hunter-v1 (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 10 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
