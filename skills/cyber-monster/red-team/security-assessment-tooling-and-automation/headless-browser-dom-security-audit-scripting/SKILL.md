---
name: headless-browser-dom-security-audit-scripting
description: "Builds Playwright headless browser security audit harnesses: CSP/Trusted-Types violation listeners, `postMessage` handler instrumentation, third-party script SRI inventory, and client-storage token inspection in isolated browser contexts. Use when automating client-side DOM and browser policy verification."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["playwright security script", "headless dom audit", "csp violation collector", "postmessage auditor"]
cwe: [CWE-79]
owasp: [A03:2021]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Headless Browser Dom Security Audit Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Driving a real browser engine from script to observe what the page actually does: which origins scripts load from, which sinks receive user-controlled data, whether a Content-Security-Policy violation fires, and what the DOM looks like after client-side rendering. Playwright gives a Chromium or Firefox context with network interception and console capture, so the audit can record a violation event instead of inferring it from source.

- **The violation event is the evidence.** `securitypolicyviolation` names the directive, the blocked URI, and the document URI; a CSP finding without it is a header-parsing guess.
- **Context isolation is the safety control.** A fresh `browser.new_context()` with no stored state keeps one target's cookies out of the next probe.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding is a CSP gap **THEN** register a `securitypolicyviolation` listener before navigation and record the first event only.
2. **IF** the page renders client-side **THEN** wait on a specific selector, not a timeout, before reading the DOM.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a reachable origin, a browser engine version, and a page action that produces the behaviour under test — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Playwright for Python or Node (`chromium.launch(headless=True)`, `browser.new_context()`, `page.on("console")`, `page.evaluate`)
- **Mandatory Self-Validation Command:** `python -m playwright install chromium && python -c "import playwright; print('ok')"`

1. Confirm the target surface: navigate once, record the document origin, the CSP header and meta policy, and every distinct script origin observed.
2. Choose the branch: network-level audit (origins, headers, mixed content), DOM-level audit (sinks and rendered output), or policy-level audit (violation events under a controlled probe).
3. Define the differential: load the page clean, then load it with one injected attribute or query parameter; the differential is a violation event or a DOM change that appears only in the probe.
4. Name the stop condition: one navigation per probe with a per-page timeout, and abort on the first violation rather than accumulating events from unrelated page activity.
5. Prove it: capture the violation event object, the document URI, and a screenshot, so the claim is reproducible without replaying the script.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `page.on("console", handler)` | Captures CSP and mixed-content messages the engine emits, which often precede a violation event. |
| `document.addEventListener("securitypolicyviolation", ...)` | The authoritative signal: directive, blockedURI, and disposition per event. |
| `browser.new_context(storage_state=None)` | Fresh cookie and cache state per probe, so one target cannot contaminate the next. |
| `page.evaluate for a DOM sink read` | Reads rendered output rather than the source template, which is where client-side injection actually lands. |

## Worked Contrast

**Header-String Audit With No Browser:**

```python
import requests

r = requests.get("https://target.example/")
csp = r.headers.get("content-security-policy", "")
print("unsafe-inline" in csp)  # BUG: says nothing about whether the page actually loads inline script
```

**Violation-Event Audit in a Real Engine:**

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    ctx = browser.new_context()
    page = ctx.new_page()
    events = []
    page.expose_function("report", lambda e: events.append(e))
    page.add_init_script("""
        document.addEventListener('securitypolicyviolation', (e) => {
            report({directive: e.violatedDirective, uri: e.blockedURI,
                    doc: e.documentURI, disposition: e.disposition});
        });
    """)
    page.goto("https://target.example/", wait_until="load")
    print(events[:3])
    browser.close()
```

**Why this matters:** A header that contains `unsafe-inline` may still be irrelevant if no inline script exists, and a header without it may be bypassed by a meta tag or a nonce-less tag the parser accepts. The violation event is emitted by the engine for the exact directive and blocked URI, which is the only form of this claim that survives review.

## When It Is NOT This Issue

- **Violation from an extension or injected script.** Browser extensions inject into every page; run a clean profile and check the blocked URI's origin.
- **Violation only under `report-only`.** A policy in report-only mode is not enforced; the finding is the mode, not the block.
- **Mixed content from a stale cached asset.** Clear the context and confirm the request is issued by the document under test.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `page.on('console')` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `headless-browser-dom-security-audit-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: headless-browser-dom-security-audit-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `page.on('console')`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile headless_browser_dom_security.py; python headless_browser_dom_security.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `headless-browser-dom-security-audit-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
