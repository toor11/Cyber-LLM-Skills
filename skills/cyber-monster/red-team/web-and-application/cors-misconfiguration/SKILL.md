---
name: cors-misconfiguration
description: "Exploits cross-origin resource sharing misconfigurations: reflected origins, null origin, wildcard with credentials, subdomain trust, and pre-flight bypass. Use when an API returns Access-Control-Allow-Origin headers."
family: web-and-application
tier: leaf
triggers: ["cors", "cors misconfiguration", "access-control-allow-origin", "acaо", "cross origin"]
cwe: [CWE-942]
owasp: [A05:2021]
attack: []
capec: [CAPEC-51]
related: [cors-misconfiguration-reflected-origin, cors-misconfiguration-credentialed-wildcard, sql-injection, cross-site-scripting]
---

# CORS Misconfiguration - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A browser enforces the same-origin policy for reads, but Cross-Origin Resource Sharing lets a server opt specific origins back in through Access-Control-Allow-Origin and Access-Control-Allow-Credentials response headers. The security decision is made entirely on the server when it computes those headers from the inbound Origin: if it reflects the request Origin, trusts null, or combines a permissive allow-origin with allow-credentials true, any attacker page can issue a credentialed cross-origin fetch and read the authenticated response. The attacker gains read access to another user's authenticated data, not a state change, which distinguishes this from CSRF. Confirmation is a differential on the Origin request header against the two allow headers in the response, with no need to exfiltrate real data.

- **Precondition chain:** An endpoint returns Access-Control-Allow-Origin derived from the request Origin, it also returns Access-Control-Allow-Credentials true (or the data is sensitive without credentials), the response body carries data the requester could not otherwise read, and a victim browser would attach its ambient cookie to the cross-origin fetch.
- **Readable differential:** The same request sent with a benign Origin versus an attacker-chosen Origin; a finding exists when the attacker Origin is echoed into Access-Control-Allow-Origin alongside credentials true, and it disappears once the server answers only exact allowlisted origins and adds Vary: Origin.
- **Empirical grounding:** CWE-942 permissive cross-domain policy, filed under OWASP Top 10:2025 A02 Security Misconfiguration; CVE-2025-50579 (Nginx Proxy Manager) is a 2025 instance where a CORS misconfiguration exposed JWT tokens to a cross-origin reader.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the server reflects the request Origin or trusts null back into the response **THEN** switch to [`cors-misconfiguration-reflected-origin`](../cors-misconfiguration-reflected-origin/SKILL.md) (1 hop)
2. **IF** a wildcard or broad subdomain trust is paired with credentials **THEN** switch to [`cors-misconfiguration-credentialed-wildcard`](../cors-misconfiguration-credentialed-wildcard/SKILL.md) (1 hop)
3. **IF** the cross-origin concern is a state change rather than a read **THEN** reclassify as request forgery and read [`csrf`](../csrf/SKILL.md)
4. **IF** the cross-origin channel is a WebSocket upgrade **THEN** treat it as Origin validation on the handshake and read [`websocket-security`](../websocket-security/SKILL.md)
5. **IF** the allow-origin is served from a cache rather than computed per request **THEN** check cache keying and read [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md)
6. **IF** the trusted origin is a takeoverable or dangling host **THEN** confirm DNS ownership and read [`subdomain-takeover`](../subdomain-takeover/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the response carries no credentials and no sensitive data for any Origin **THEN** STOP and record a public-API non-finding rather than reporting a permissive header

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Cross-origin concern is a state-changing request | [`csrf`](../csrf/SKILL.md) | Invariant is request-origin proof, not read access across origins |
| Channel is a WebSocket upgrade | [`websocket-security`](../websocket-security/SKILL.md) | Invariant is Origin validation on the WS handshake under CWE-1385 |
| Allow-origin served from a shared cache | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | Invariant is cache-key integrity, a different control |
| Target matches `cors-misconfiguration-reflected-origin` | [`cors-misconfiguration-reflected-origin`](../cors-misconfiguration-reflected-origin/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `cors-misconfiguration-credentialed-wildcard` | [`cors-misconfiguration-credentialed-wildcard`](../cors-misconfiguration-credentialed-wildcard/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the header computation, not the route.** Find where Access-Control-Allow-Origin is set and whether its value is a constant, a reflection of the request Origin, or a lookup; record whether Access-Control-Allow-Credentials is also emitted.
2. **Classify the data behind the endpoint.** A read of authenticated, per-user data is in scope; a public, credential-free response is not, and this triage decides whether a permissive header even matters.
3. **Choose the header-pair oracle.** The only oracle needed is the response pair Access-Control-Allow-Origin and Access-Control-Allow-Credentials against the Origin you sent; this leaks nothing and fully falsifies the hypothesis.
4. **Record a benign-Origin baseline.** Send a legitimate Origin and capture both allow headers so the trusted behaviour is known before probing.
5. **Apply the attacker-Origin differential.** Resend with an attacker-controlled Origin and with null, comparing the allow headers; an echoed attacker Origin with credentials true selects the finding from evidence.
6. **Stop condition.** Stop when the probe either (a) echoes the attacker Origin with credentials true and reverts under an exact allowlist, (b) returns a fixed allowlisted value or omits the header for foreign origins, or (c) would require reading another user's real data to prove impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a response that names the attacker-chosen Origin in Access-Control-Allow-Origin together with Access-Control-Allow-Credentials true, reproducible from a single changed Origin header, plus the sensitivity of the body. A permissive wildcard without credentials on public data is not proof.
8. **Close with the structural fix and verify.** Replace reflection with an exact-match allowlist, never pair credentials with a wildcard, add Vary: Origin, and omit the header entirely for unknown origins, then replay the attacker-Origin differential to confirm the header is gone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Access-Control-Allow-Origin echoing the exact inbound Origin value | Proves per-request reflection on any framework where the Origin header is copied into the response |
| Access-Control-Allow-Credentials: true returned alongside a reflected origin | Proves credentialed cross-origin reads are permitted, the condition that makes reflection dangerous |
| Access-Control-Allow-Origin: null returned for an Origin of null | Proves sandboxed iframes and data URIs are trusted, a bypass usable from attacker-framed content |
| A missing Vary: Origin header on a per-origin response | Proves cache keys ignore Origin, so a shared cache may serve one origin's allow header to another |
| Access-Control-Allow-Origin: * on an endpoint returning per-user data | Proves a public-wildcard policy on authenticated data, readable only when credentials are not required |
| An authenticated JSON body returned to a cross-origin fetch with cookies attached | Proves the read is both reachable and sensitive, completing the CORS read-access finding |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// Reflects any Origin and allows credentials: every site becomes trusted
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});
```

**Hardened pattern:**

```javascript
const ALLOWED = new Set(["https://app.example", "https://admin.example"]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
  }
  next();
});
```

**Why this matters:** The vulnerable middleware reflects whatever Origin arrives and always allows credentials, so any attacker page reads authenticated responses. The fix answers only origins in an exact-match set, emits the allow headers solely for those, and adds Vary: Origin so a shared cache cannot leak one origin's policy to another.

## When It Is NOT This Issue

- **Public API with wildcard and no credentials:** an endpoint returning non-sensitive data with Access-Control-Allow-Origin: * and no cookies is behaving as designed.
- **Reflection without credentials on public data:** echoing the Origin but never setting credentials true leaves no authenticated read to steal.
- **Exact allowlist already enforced:** a server that returns the header only for a closed set of origins and omits it otherwise is safe even though it varies by Origin.
- **State change concern:** a cross-origin write blocked by SameSite or a token is a CSRF question, not a CORS read finding.
- **Preflight rejected:** an OPTIONS preflight that the server refuses for the attacker Origin means the credentialed read never proceeds.
- **Non-browser client:** a server-to-server consumer ignores CORS entirely, so a permissive header does not expose anything a browser victim could read.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cors-misconfiguration` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cors-misconfiguration` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cors-misconfiguration
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-942 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cors-misconfiguration-reflected-origin`](../cors-misconfiguration-reflected-origin/SKILL.md) - Web and Application (leaf)
- [`cors-misconfiguration-credentialed-wildcard`](../cors-misconfiguration-credentialed-wildcard/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cors-misconfiguration` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-942`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 46 |
| Distinct dataset sources | 11 |
| Top sources | OffsecCyber (25), hackerone_disclosed_reports (6), SecEval/owasp_wstg (3), CYBER_CPT/oxdf (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
