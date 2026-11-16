---
name: crlf-and-header-injection
description: Injects carriage-return and line-feed sequences to split HTTP messages, poison headers, inject response bodies, and reach cache and log poisoning. Use when input lands in a header value, cookie, filename or redirect target.
family: web-and-application
tier: leaf
triggers: ["crlf injection", "header injection", "response splitting", "log injection", "http response splitting"]
cwe: [CWE-93, CWE-113]
owasp: [A03:2021]
attack: []
capec: [CAPEC-105]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# CRLF and Header Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

An application copies a request value into an outgoing HTTP message, a response header such as Location or Set-Cookie, a log line, or a header forwarded upstream, without stripping carriage-return and line-feed bytes. Because CR and LF are the structural delimiters of the HTTP header block, an un-neutralised %0d%0a lets the attacker terminate the current header and inject new ones, and a double CRLF ends the header block entirely to inject a response body. The security decision is the header-writing routine's handling of control characters, not content filtering. The attacker gains forged headers, a planted Set-Cookie, response splitting that feeds cache poisoning or reflected script, or falsified log entries. Verification sends a benign injected header and checks whether it materialises as a real header, never poisoning shared infrastructure.

- **Precondition chain:** A request value reaches an outgoing header, cookie, redirect target, or log sink, the writer does not strip or reject CR and LF bytes, the downstream agent parses the injected delimiters as structure, and the forged header, body, or log line is observable.
- **Readable differential:** The same value sent plain versus the same value carrying %0d%0a and an injected header name; a finding exists when the injected header appears as a distinct header in the response, and it vanishes once the writer strips or rejects CR and LF.
- **Empirical grounding:** CWE-93 CRLF injection and CWE-113 HTTP response splitting under OWASP A03:2021 Injection; CVE-2025-40927 (CGI::Simple response splitting bypassed via URL-encoded values), GHSA-5v79-p56f-x7c4 (Pi-hole CRLF injection, CWE-113), and GHSA-h3x8-ppwj-6vcj (HTTP.jl header injection and response splitting) are 2025 instances.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the injected value is a Host or X-Forwarded-Host header **THEN** treat it as trusted-host derivation and read [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md)
2. **IF** the split response poisons a shared cache entry **THEN** check cache keying and read [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md)
3. **IF** the CR and LF land only in a redirect Location value **THEN** treat it as redirect-target allowlisting and read [`open-redirect`](../open-redirect/SKILL.md)
4. **IF** the injection is into an SMTP or email header rather than HTTP **THEN** reclassify as mail header injection and read [`email-header-injection`](../email-header-injection/SKILL.md)
5. **IF** only a line feed passes while carriage return is stripped **THEN** test the LF-only variant explicitly because some parsers accept bare LF as a delimiter
6. **IF** the injected body executes as script in the victim browser **THEN** chain the response-splitting body into [`cross-site-scripting`](../cross-site-scripting/SKILL.md)
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the writer strips CR and LF or the runtime rejects them before the sink **THEN** STOP and record a verified non-finding rather than reporting the raw reflection

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Injected value is a Host or forwarded-host header | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Invariant is trusted host derivation, a sibling header flaw |
| Split response poisons a shared cache | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | Invariant is cache-key and response integrity |
| CRLF lands in an SMTP or email header | [`email-header-injection`](../email-header-injection/SKILL.md) | Invariant is mail header neutralization per CVE-2025-59419 |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the header or log writer and the value it copies.** Identify every sink where request input becomes an outgoing header, a Set-Cookie, a redirect Location, or a log record, and note the writer API used.
2. **Classify the delimiter handling.** Determine whether the runtime or framework already rejects CR and LF, strips one of them, or passes both through; modern servers often block full CRLF but not a bare LF.
3. **Choose a benign injected-header oracle.** The oracle is whether a harmless injected header name appears in the response; it proves the split without touching caches, cookies that matter, or logs that feed alerts.
4. **Record a plain-value baseline.** Send the value with no control characters and capture the exact response header set so an added header stands out.
5. **Apply the CRLF differential.** Resend with %0d%0a followed by a unique benign header, and separately with a bare %0a, comparing the response headers; a new header materialising selects the finding and the working delimiter.
6. **Stop condition.** Halt when the probe either (a) produces the injected benign header and reverts once CR and LF are stripped, (b) shows the value flattened with no new header across baselines, or (c) would require poisoning a real cache, planting a real session cookie, or forging alertable logs to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a unique benign header appearing in the response (or a split body boundary) caused by one injected %0d%0a or %0a, reproducible against a plain baseline, plus the writer source line that copies the value. A reflected literal \r\n inside a body is not proof of header splitting.
8. **Close with the structural fix and verify.** Reject or strip CR and LF in the header writer, use a framework setter that encodes control characters, and allowlist redirect targets, then replay the CRLF differential and confirm no injected header or body boundary appears.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| %0d%0a in a parameter that is copied into a response header | Proves the header writer passes CR and LF through on any stack that concatenates input into headers |
| %0a alone accepted where %0d%0a is blocked | Proves a bare-LF parser differential, the variant that defeated several CRLF filters |
| %0d%0aSet-Cookie: injected and reflected as a real cookie header | Proves session-fixation reach where the attacker plants a cookie via the split |
| A double CRLF followed by markup rendered as a response body | Proves full response splitting that feeds reflected script or a cache-poisoning payload |
| URL-encoded CR and LF decoded only after a validation check | Proves an order-of-operations bypass like the CGI::Simple URL-encoded-value case |
| A newline in a parameter producing a second forged line in an application log | Proves log forging where injected entries mislead monitoring on the logging stack |

## Worked Contrast

**Vulnerable pattern:**

```python
def redirect_next(req, resp):
    target = req.params.get("next", "/")
    # raw CR/LF in the value splits the header block and injects new headers
    resp.headers["Location"] = "https://app.example/" + target
    resp.status = 302
    return resp
```

**Hardened pattern:**

```python
from urllib.parse import quote

ALLOWED_PATHS = {"/", "/dashboard", "/settings"}

def redirect_next(req, resp):
    target = req.params.get("next", "/")
    if target not in ALLOWED_PATHS:
        raise ValueError("redirect target is not in the allow set")
    # percent-encode so CR and LF can never reach the header as structure
    resp.headers["Location"] = "https://app.example" + quote(target, safe="/")
    resp.status = 302
    return resp
```

**Why this matters:** The vulnerable handler concatenates the raw next value into the Location header, so %0d%0a injects arbitrary headers or a split body. The fix accepts only a closed set of paths and percent-encodes the value, so no carriage return or line feed can ever be emitted as header structure.

## When It Is NOT This Issue

- **Runtime rejects CR and LF:** modern server APIs that raise on control characters in header values stop the split before it reaches the wire.
- **Reflected \r\n inside a body only:** literal backslash-r-backslash-n shown in a JSON string is text, not an actual delimiter the parser acts on.
- **Value flattened to a space:** a framework that replaces newlines with spaces removes the structural break even if the characters were accepted.
- **Log sink with structured encoding:** a JSON or key-value logger that escapes newlines cannot be line-forged by an injected LF.
- **Redirect allowlist already enforced:** a Location built only from a closed path set never carries attacker CR or LF.
- **Self-only cookie scope:** an injected Set-Cookie that lands only in the attacker's own browser affects no victim.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `crlf-and-header-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `crlf-and-header-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: crlf-and-header-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-93, CWE-113 | Mapping: A03:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `crlf-and-header-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-93, CWE-113`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 50 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (26), hackerone_disclosed_reports (12), ctf-solver-dataset (3), CYBER_CPT/nuclei_templates (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
