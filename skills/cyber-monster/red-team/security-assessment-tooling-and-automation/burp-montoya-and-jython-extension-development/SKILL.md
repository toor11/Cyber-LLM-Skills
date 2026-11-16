---
name: burp-montoya-and-jython-extension-development
description: "Builds Burp Suite extensions using the modern Java Montoya API (and legacy IBurpExtender migration): passive AuditIssue checks, HttpHandler traffic normalizers, custom session-handling macros, and authorization matrix comparators without blocking the Swing UI thread. Use when extending Burp Suite for custom protocol or authz auditing."
family: security-assessment-tooling-and-automation
tier: flagship
triggers: ["burp extension", "montoya api", "burp plugin", "passive scan check", "burpextender"]
cwe: [CWE-862]
owasp: [A01:2021]
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, mitmproxy-addon-scripting, openapi-and-graphql-schema-auditor-scripting]
---


# Burp Montoya and Jython Extension Development - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **flagship** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)

## Mechanism and Preconditions

Burp Suite extensions written against the Montoya API: register an `HttpHandler` to observe or adjust traffic in both directions, a `ScanCheck` to contribute passive or active audit checks, and a `ContextMenuItemsProvider` to expose analyst actions. The engineering discipline is that an extension must be inert when the user has not enabled it, must not mutate requests outside its declared scope, and must report through `api.logging()` rather than stdout.

- **Registration is the permission model.** Only what you register in `initialize` can affect traffic; a handler that rewrites every request silently changes other testers' results.
- **Bulk send goes through the task engine.** The 2026.7 `RequestExecutionEngine` keeps concurrency, throttling, and retries inside Burp's resource pools instead of spawning threads the user cannot stop.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the extension only reads traffic **THEN** implement the passive `doPassiveScan` path and never touch request bytes.
2. **IF** the extension must send many requests **THEN** use `api.http().createRequestEngine()` with a `RequestEngineOptions` name so the run appears as a stoppable dashboard task.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a Burp version whose Montoya artifact matches the API used, and a scope rule the extension respects — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Montoya API 2026.7 (`burp.api.montoya.*`), Java 21, `RequestExecutionEngine` for bulk sends, `api.logging()` for output
- **Mandatory Self-Validation Command:** `gradle build && unzip -l build/libs/extension.jar`

1. Confirm the target surface: decide whether the extension observes (`HttpHandler`), audits (`ScanCheck`), or acts on selection (`ContextMenuItemsProvider`), and register only that surface.
2. Choose the branch: passive check for response-only heuristics, active check for a controlled probe, handler for header or parameter normalisation.
3. Define the differential: for an active check, send the baseline request and the probe request through `api.http().sendRequest` and compare a specific response attribute; for a passive check, record the exact condition that made the response match.
4. Name the stop condition: a per-host request ceiling inside the check, because Burp runs checks concurrently against a host the user did not expect to load.
5. Prove it: each issue carries the request, the response, and the marker offsets, so a reviewer can replay it from the dashboard without re-running the scan.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `implements HttpHandler` | Observes every request and response Burp sends; registering it is a deliberate, reviewable decision to see all traffic. |
| `implements ScanCheck with doPassiveScan` | Contributes findings without sending new requests, which is the only safe default for an extension distributed to other testers. |
| `api.http().createRequestEngine()` | Bulk sender bound to Burp's resource pool; the run is visible and cancellable on the dashboard. |
| `api.logging().logToOutput` | Extension output that lands in Burp's own log rather than a detached stdout nobody reads. |

## Worked Contrast

**Extension That Mutates Everything and Spawns Its Own Threads:**

```java
public void initialize(MontoyaApi api) {
    api.http().registerHttpHandler(new HttpHandler() {
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {
            // BUG: rewrites every response for every tool, no scope check, no user opt-in
            return ResponseReceivedAction.continueWith(r);
        }
    });
    new Thread(() -> { /* BUG: unbounded sends outside Burp's task engine */ }).start();
}
```

**Scope-Aware Handler Plus Engine-Backed Bulk Send:**

```java
public void initialize(MontoyaApi api) {
    api.http().registerHttpHandler(new HttpHandler() {
        public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived r) {
            if (!api.scope().isInScope(r.initiatedBy().httpService().host())) {
                return ResponseReceivedAction.continueWith(r);
            }
            api.logging().logToOutput("observed " + r.initiatedBy().httpService());
            return ResponseReceivedAction.continueWith(r);
        }
    });
}

void bulk(MontoyaApi api, List<HttpRequest> reqs) {
    RequestExecutionEngine engine = api.http().createRequestEngine(
        RequestEngineOptions.requestEngineOptions().withName("audit-sweep"));
    reqs.forEach(engine::queue);
    engine.sendAll();
}
```

**Why this matters:** The scope check is what makes the handler safe to leave installed: without it the extension edits traffic in tools the tester never pointed at the target. Routing bulk requests through `RequestExecutionEngine` keeps concurrency inside Burp's resource pool, where the user can pause or cancel it.

## When It Is NOT This Issue

- **Extension loaded but not enabled.** A registered handler still fires for passive observation; check whether the finding requires the extension to have been active during the session.
- **Burp's own scanner artefact.** Requests carrying Burp's scanner headers are the tool's traffic, not the target's behaviour.
- **Community vs Professional API.** `RequestExecutionEngine` is Professional-only; an extension that fails on Community is a licensing boundary, not a defect.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `BurpExtension` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `burp-montoya-and-jython-extension-development` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: burp-montoya-and-jython-extension-development
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `BurpExtension`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile burp_montoya_and_jython.py; python burp_montoya_and_jython.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`async-http-and-dns-audit-scripting`](../async-http-and-dns-audit-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `burp-montoya-and-jython-extension-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-862`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 9 |
| Distinct dataset sources | 2 |
| Top sources | bugbounty-hunter-v1 (5), OffsecCyber (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
