---
name: mitmproxy-addon-scripting
description: "Authors Python mitmproxy addons using event hooks (`request`, `response`, `websocket_message`): traffic diffing, header/cookie policy auditing, GraphQL/JSON schema capture, and HAR/JSONL export for API security testing. Use when automating intercepting-proxy inspection in Python."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["mitmproxy addon", "mitmdump script", "httpflow python", "mitmproxy hook", "proxy automation"]
cwe: [CWE-319]
owasp: [A05:2021]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, openapi-and-graphql-schema-auditor-scripting]
corpus_sparse: true
---


# Mitmproxy Addon Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Intercepting and inspecting traffic with a mitmproxy addon: implement an event hook such as `request` or `response`, read or adjust the flow, and emit a record. The audit use is a controlled observation point — confirming what a client actually sends, whether a token is bound to a device, whether a response carries insecure headers — rather than a rewriting proxy that changes the application under test.

- **Hooks run per flow; state must be scoped.** A counter or cache in the addon persists across hosts, so key it by flow identifier or the trace conflates targets.
- **Logging goes through `logging`, not `ctx.log`.** The addon-facing logging shim was deprecated in favour of the standard library, and a handler you register is the supported way to capture records.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you only need to observe **THEN** implement `response(self, flow)` and never assign to `flow.request`.
2. **IF** streaming is enabled **THEN** expect `response` to fire before `request` completes, and do not assume ordering.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a client configured to trust the proxy CA, and one user action whose traffic you can identify — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** mitmproxy 12.x addon API (`mitmproxy.http.HTTPFlow`, `addons = [...]`), `mitmdump -s addon.py`, standard `logging` for output
- **Mandatory Self-Validation Command:** `mitmdump --version && python -c "import mitmproxy; print(mitmproxy.__version__)"`

1. Confirm the target surface: start the proxy with the addon, drive one user action, and record which hosts and paths the action touched.
2. Choose the branch: request observation, response observation, or a WebSocket frame hook when the protocol upgrades.
3. Define the differential: capture the action with the addon and without it, and require the same request count; a different count means the addon altered behaviour.
4. Name the stop condition: a flow count or a host filter, so the trace covers the action and nothing else.
5. Prove it: emit one JSON line per flow with method, host, path, status, and a body hash, then attach the line to the finding.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `def response(self, flow)` | Per-response hook; reading `flow.response.headers` is the smallest observation that answers a header question. |
| `flow.request.headers and flow.response.content` | The two objects an audit reads; mutating them changes the application under test. |
| `logging.getLogger plus a Handler` | The supported way to capture addon output since the logging shim was deprecated. |
| `mitmproxy.dns.DNSMessage` | Current class name for DNS flows; `mitmproxy.dns.Message` was renamed in mitmproxy 12. |

## Worked Contrast

**Addon That Rewrites Every Response:**

```python
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # BUG: strips security headers from every host, so findings reflect the addon, not the server
    for h in ("content-security-policy", "strict-transport-security"):
        flow.response.headers.pop(h, None)
    print(flow.request.pretty_url)
```

**Read-Only Addon With Structured Records:**

```python
import hashlib
import json
import logging

from mitmproxy import http

log = logging.getLogger("audit")


def response(flow: http.HTTPFlow) -> None:
    body = flow.response.content or b""
    log.info(json.dumps({
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "status": flow.response.status_code,
        "sha256": hashlib.sha256(body).hexdigest(),
        "csp": "content-security-policy" in flow.response.headers,
    }))

addons = []
```

**Why this matters:** Deleting security headers changes what the browser enforces, so any header finding afterwards describes the proxy. Emitting a hash and a header-presence flag records the server's own behaviour, which is the only thing the audit can report.

## When It Is NOT This Issue

- **Header missing because the addon removed it.** Always capture once with an unmodified addon before reporting header behaviour.
- **Proxy CA causing a pinning failure.** A client that refuses the proxy certificate is evidence of pinning, not of a broken TLS configuration.
- **HTTP/2 to HTTP/1.1 downgrade at the proxy.** Protocol differences in the capture are the proxy's doing, not the server's.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `http.HTTPFlow` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `mitmproxy-addon-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: mitmproxy-addon-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `http.HTTPFlow`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile mitmproxy_addon_scripting.py; python mitmproxy_addon_scripting.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`async-http-and-dns-audit-scripting`](../async-http-and-dns-audit-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `mitmproxy-addon-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-319`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
