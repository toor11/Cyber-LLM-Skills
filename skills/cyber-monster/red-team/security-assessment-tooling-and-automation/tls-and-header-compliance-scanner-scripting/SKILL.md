---
name: tls-and-header-compliance-scanner-scripting
description: "Writes non-intrusive TLS handshake, certificate-chain, and HTTP security header compliance scanners using `sslyze`/`ssl` and `httpx`: checking protocol floors, cipher suites, OCSP/SCT presence, HSTS, CSP, frame-ancestors, and cookie flags across asset inventories. Use when scripting transport and header compliance checks."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["sslyze script", "tls compliance scanner", "security header checker python", "certificate expiry audit"]
cwe: [CWE-295, CWE-693]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# TLS and Header Compliance Scanner Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Scripted assessment of a service's TLS and HTTP security posture: enumerate supported protocol versions and cipher suites, read the certificate chain and validity, then check response headers for HSTS, CSP, and related policies. The audit discipline is separating what the server negotiates (protocol, cipher, certificate) from what it merely advertises (headers), because only the first is enforced by the transport.

- **Negotiation is evidence; a header is a request.** A supported TLS 1.0 handshake is observed behaviour; a missing HSTS header is a policy gap whose impact depends on the client.
- **The chain is checked, not just the leaf.** Validity dates and trust anchor come from verifying the chain with the system store, not from parsing the leaf's dates.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the check is protocol support **THEN** open one handshake per version with an explicit context and record the negotiated cipher.
2. **IF** the check is a header **THEN** compare the same URL across two requests and require the header set to be stable before reporting its absence.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a reachable host and port, a TLS library version, and a defined header policy to compare against — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python `ssl` (`SSLContext`, `minimum_version`, `maximum_version`) or `sslyze` for enumeration, plus `httpx` for header capture
- **Mandatory Self-Validation Command:** `python -c "import ssl, httpx; print(ssl.OPENSSL_VERSION)"`

1. Confirm the target surface: resolve the host, record the IPs the name maps to, and confirm the port is in the assessment scope.
2. Choose the branch: protocol enumeration, cipher enumeration, certificate chain validation, or header policy comparison.
3. Define the differential: for a header, capture the response twice and require identical header sets; for a protocol, attempt a handshake per version and record which complete.
4. Name the stop condition: one handshake per version, a connection timeout, and no repeated negotiation on failure.
5. Prove it: record the negotiated version, cipher, certificate subject and validity, plus the response header block, so each claim maps to one observation.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) with minimum_version` | Forces a specific handshake attempt; without pinning the version you only observe the library's default. |
| `check_hostname=True plus load_default_certs` | Makes chain and name verification part of the observation instead of a separate opinion. |
| `getpeercert() for subject, issuer and validity` | The chain's own claims, which the verification result then confirms or rejects. |
| `Strict-Transport-Security max-age` | The header that makes a browser enforce HTTPS; its absence is only meaningful on a response that is otherwise stable. |

## Worked Contrast

**Header Check Without a Baseline or a Handshake:**

```python
import httpx

r = httpx.get("https://target.example/")
if "strict-transport-security" not in {k.lower() for k in r.headers}:
    print("missing HSTS")  # BUG: no baseline, no redirect target, no protocol observation
```

**Version-Pinned Handshake Plus Stable Header Comparison:**

```python
import socket
import ssl

import httpx

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.check_hostname = True
ctx.load_default_certs()

with socket.create_connection(("target.example", 443), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname="target.example") as tls:
        print(tls.version(), tls.cipher()[0])
        print(tls.getpeercert()["notAfter"])

headers = [httpx.get("https://target.example/", timeout=10).headers for _ in range(2)]
stable = {k.lower() for k in headers[0]} == {k.lower() for k in headers[1]}
print("stable", stable, "hsts", "strict-transport-security" in {k.lower() for k in headers[0]})
```

**Why this matters:** A missing header on one response may be a redirect, a cached edge copy, or a policy applied only to some routes, so the absence is not yet a finding. Pinning the handshake version records what the server actually negotiates, and requiring two identical header sets makes the header claim about the server rather than about one response.

## When It Is NOT This Issue

- **Header absent on a redirect response.** Policy headers belong on the final response and often on the redirect too; check which one you captured.
- **Protocol version reflects the client's default.** A TLS 1.3 handshake does not prove TLS 1.0 is disabled; enumerate each version explicitly.
- **Certificate warning from a name mismatch on an internal host.** A hostname mismatch on a host reached by IP is expected; report the certificate's actual names instead.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `ssl.create_default_context` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `tls-and-header-compliance-scanner-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: tls-and-header-compliance-scanner-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `ssl.create_default_context`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile tls_and_header_compliance.py; python tls_and_header_compliance.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `tls-and-header-compliance-scanner-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-295, CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
