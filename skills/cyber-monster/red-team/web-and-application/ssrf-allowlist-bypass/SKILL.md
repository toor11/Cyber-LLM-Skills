---
name: ssrf-allowlist-bypass
description: SSRF allowlist and filter bypass. Covers bypassing URL allowlists and blocklists with parser differentials, DNS rebinding, decimal and octal IP forms, redirect chains, and credential or fragment tricks. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ssrf bypass", "ssrf allowlist bypass", "dns rebinding", "url parser bypass"]
cwe: [CWE-918]
owasp: [A10:2021]
attack: [T1190]
capec: [CAPEC-664]
related: [ssrf, ssrf-cloud-metadata, ssrf-internal-service-pivot, ssrf-protocol-smuggling]
parent: ssrf
---

# SSRF Allowlist Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

An SSRF allowlist bypass turns on a disagreement between the component that validates the URL string and the component that actually connects. The validator reads a hostname and decides it is allowed; the resolver later maps that name to an address, and the HTTP client follows redirects or accepts a scheme the validator never considered. Each layer parses the URL differently, so a decimal, octal, hex, or IPv6 form, a `user@host` credential trick, a short-TTL rebinding record, or a 302 from an allowed host to an inward target slips through. The security decision should be made on the final resolved address at connect time, but the code makes it on the pre-resolution string, leaving a time-of-check to time-of-use gap that reaches loopback, link-local, or RFC1918 destinations the caller cannot.

- **Precondition chain:** A request-controlled URL reaches a server-side fetch, the validator decides on the string while the resolver or client decides the real address later, and the resolved destination can be an inward address the caller could not reach directly.
- **Readable differential:** An allowed hostname that resolves or redirects inward versus the literal inward address; a finding exists when the encoded, rebinding, or redirect form reaches the internal destination while the literal form is rejected, and it closes when the server resolves once and validates the pinned address.
- **Empirical grounding:** CWE-918 under OWASP Top 10:2025 A01:2025 Broken Access Control; CVE-2025-64709 (Typebot webhook SSRF) shows an allowlist and metadata control defeated by custom header injection, and the parser-differential class underlies decimal, octal, and IPv6 bypasses.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to match an allowlist or filter bypass **THEN** start at the parent class [`ssrf`](../ssrf/SKILL.md) first (1 hop)
2. **IF** the destination is fixed by configuration and only a path is appended **THEN** classify as a non-finding; path control is a different issue
3. **IF** an allowed hostname resolves to an inward address **THEN** test the resolve-versus-connect gap with a rebinding or short-TTL record
4. **IF** the target is link-local metadata **THEN** switch to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) (1 hop)
5. **IF** the target is an internal TCP service **THEN** switch to [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) (1 hop)
6. **IF** the parameter accepts a non-HTTP scheme **THEN** switch to [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) (1 hop)
7. **IF** no response or error is reflected **THEN** switch to [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) (1 hop) and move to an OAST or timing oracle
8. **IF** the bypass is really an open redirect used to pivot **THEN** read [`open-redirect`](../open-redirect/SKILL.md) for the allowlist-escape angle
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
10. **IF** the destination is never request-derived after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Validation on the string, resolution separate | [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) | Inward resolution reaches the instance role, a credential-exposure impact |
| Allowed host 302s to an inward target | [`open-redirect`](../open-redirect/SKILL.md) | The escape is a redirect on a trusted host, a different primitive |
| Only a callback, no body | [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) | Confirmation moves to out-of-band correlation |
| Need parent class methodology | [`ssrf`](../ssrf/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the fetch primitive and how the URL arrives.** Note whether the destination is a whole URL, a host only, or a path appended to a fixed base, and which library issues the request. Only a request-controlled host or scheme is a candidate.
2. **Read the validate-then-connect order in code.** Identify the parse step, the allowlist check, the resolver call, and the connect call. The gap between resolve and connect, and any trust in the pre-resolution string, is where the bypass lives.
3. **Fix an outward baseline.** Point the parameter at a host you control and confirm the server issues the request with its own client, capturing the User-Agent and whether redirects are followed, which defines the branch set.
4. **Test the disagreement, not the payload.** Send an allowed hostname that resolves inward, an allowed host that 302s inward, and encoded IPv4 or IPv6 forms of an inward address, each probing a different parser between validator and connector.
5. **Separate resolution from connection.** Confirm whether a DNS lookup alone occurs or an actual connection follows; a rebinding record that changes between the validator lookup and the client lookup proves the time-of-check gap directly.
6. **Stop condition.** Halt when a form reaches an inward destination the caller cannot, shown against the outward baseline, or is rejected identically for every encoded and redirect form, or would require reading real internal data to advance. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is a fetch issued by the server, evidenced against the outward baseline, landing on an inward address through a form the literal inward address is blocked for, plus the code line that validates the string rather than the resolved address. A DNS lookup alone proves resolution, not connection.
8. **Close with the structural fix.** Resolve the host once, reject any answer in loopback, link-local, or RFC1918 ranges, pin that address for the connection, disable redirects or re-validate every hop, and restrict schemes to the one the feature needs. Verify by replaying the encoded and rebinding forms against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Decimal, octal, or hex IPv4 such as 2130706433 reaching the connector | Proves the validator and the resolver normalise differently, a parser differential on common HTTP clients |
| An allowed hostname whose DNS answer is an RFC1918 or loopback address | Proves the control trusts the string, not the resolved address, exploitable via a short-TTL or rebinding record |
| A 302 from an allowed host to an inward target that the client follows | Proves redirects are not re-validated, so the allowlist covers only the first hop |
| A `user@internal` userinfo trick in the URL | Proves the validator parses authority differently from the client, pointing the real connection inward |
| IPv6 forms such as [::1] or ::ffff:127.0.0.1 passing the filter | Proves the denylist covers IPv4 text only while the client dials IPv6 loopback |
| A rebinding record whose address changes between validation and connection | Proves the resolve-versus-connect time-of-check gap directly on the target stack |
| A custom header injected into the fetch to satisfy a metadata guard | Proves a filter bypass of the kind seen in the 2025 Typebot webhook SSRF, reaching protected endpoints |

## Worked Contrast

**Vulnerable pattern:**

```python
import urllib.parse
import requests

def import_feed(url: str) -> bytes:
    host = urllib.parse.urlsplit(url).hostname or ""
    # Suffix allowlist on the string; the client resolves and connects separately
    if not host.endswith("feeds.example"):
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5, allow_redirects=True).content
```

**Hardened pattern:**

```python
import ipaddress
import socket
import urllib.parse
import requests

ALLOWED = {"feeds.example"}

def import_feed(url: str) -> bytes:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in {"http", "https"} or parts.hostname not in ALLOWED:
        raise ValueError("host or scheme not allowed")
    addr = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)[0][4][0]
    ip = ipaddress.ip_address(addr)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError("resolves to a non-public address")
    return requests.get(url, timeout=5, allow_redirects=False).content
```

**Why this matters:** The defect uses a suffix string check and then lets the client resolve and follow redirects, so a name like feeds.example.attacker.test, a rebinding record, or a 302 reaches inward. The fix uses an exact host set, resolves once, rejects every non-public answer, pins the address, and refuses redirects, so the decision is made on what the server will actually dial.

## When It Is NOT This Issue

- **Fixed base URL, path only:** a connector that appends a path to a configured host is not allowlist bypass; the host is not attacker-controlled.
- **DNS lookup without a connection:** an OAST DNS hit from a validation pre-resolve does not prove the client connected inward.
- **Redirect to another public host:** following a 302 to a second external site is a validation gap, not internal access.
- **Egress firewall refuses inward:** the parser gap exists but a network policy blocks the connection, so it is a code defect at reduced severity.
- **Rebinding defeated by pinning:** if the client already resolves once and pins, a changing record cannot swing the connection.
- **Literal inward address simply blocked:** rejection of 127.0.0.1 proves nothing about encoded or rebinding forms, so test those before concluding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssrf-allowlist-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssrf-allowlist-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssrf-allowlist-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-918 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) - Web and Application (leaf)
- [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) - Web and Application (leaf)
- [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) - Web and Application (leaf)
- [`ssrf-blind-ssrf`](../ssrf-blind-ssrf/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssrf-allowlist-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 26 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (13), CYBER_CPT/osv (3), bugbounty-hunter-v1 (2), ctf-solver-dataset (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
