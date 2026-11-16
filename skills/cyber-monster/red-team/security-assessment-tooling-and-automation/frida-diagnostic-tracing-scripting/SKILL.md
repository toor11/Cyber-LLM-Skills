---
name: frida-diagnostic-tracing-scripting
description: "Writes TypeScript/JavaScript Frida diagnostic instrumentation scripts for authorized mobile and desktop security reviews: non-destructive crypto/TLS/IPC parameter logging, keystore/keychain API inspection, Objective-C/Java method overload hooks, and structured JSON message emission to Python hosts. Use when building runtime MASVS/API verification scripts."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["frida script authoring", "interceptor.attach", "java.perform frida", "objc.classes frida"]
cwe: [CWE-295]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Frida Diagnostic Tracing Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Runtime instrumentation with Frida to observe what a process does rather than what its bytes suggest: hook an exported function with `Interceptor.attach`, read arguments and return values in `onEnter`/`onLeave`, or hook a Java/Objective-C method through the language bridge. The audit value is a trace correlated to a user action, not a hook that fires continuously.

- **Hook the narrowest target.** `Process.getModuleByName(...).getExportByName(...)` pins one function in one module; a wildcard hook over every export produces a trace too large to attribute.
- **Read, do not rewrite.** Changing arguments or return values turns a diagnostic trace into an untested patch and invalidates the observation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a Java or Kotlin method **THEN** resolve the class with `Java.use` inside `Java.perform` and hook the overload explicitly.
2. **IF** the function is too small to patch **THEN** note that Frida's force-attach option can overwrite adjacent bytes, and prefer a different anchor.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an attachable process, the module and symbol names resolved, and one user action that should trigger the hook — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Frida 17.x (`Process.getModuleByName`, `Module.getExportByName`, `Interceptor.attach(target, {onEnter, onLeave})`), `frida -U -l script.js -f <app>`
- **Mandatory Self-Validation Command:** `frida --version && frida-ps -U`

1. Confirm the target surface: list modules and exports, pick the single symbol that must be called for the behaviour under test, and record the module build id.
2. Choose the branch: native export hook for a C function, `Java.perform` for a managed method, `ObjC.classes` for a selector, or `Stalker` when the call graph itself is the question.
3. Define the differential: run the action without the hook and with it, and require the trace to appear only for the action under test; a hook that fires on startup is instrumentation noise.
4. Name the stop condition: a call count or a time window, then detach; leaving hooks installed changes timing and can mask the behaviour.
5. Prove it: print the arguments, the return value, and a monotonic timestamp per call, then correlate the trace to the user action that produced it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Process.getModuleByName("libtarget.so").getExportByName("parse")` | Pins one symbol in one module; static `Module.` methods were removed in Frida 17 and are a common stale-API error. |
| `Interceptor.attach(target, {onEnter(args){}, onLeave(retval){}})` | The core observation primitive; reading `args[n]` and `retval` is the whole diagnostic. |
| `Java.perform(() => Java.use("com.app.Auth").login.overload('java.lang.String'))` | Resolves one overload, which avoids hooking every method with the same name. |
| `send({...}) plus a Python message handler` | Moves structured records off the device into a log a reviewer can diff. |

## Worked Contrast

**Wildcard Hook With No Attribution:**

```javascript
// BUG: hooks every export in every module, rewrites the return value, no attribution
for (const m of Process.enumerateModules()) {
  for (const e of m.enumerateExports()) {
    try { Interceptor.attach(e.address, { onLeave(r) { r.replace(ptr(1)); } }); } catch (err) {}
  }
}
```

**Single-Symbol Read-Only Trace With Correlation:**

```javascript
const mod = Process.getModuleByName("libauth.so");
const fn = mod.getExportByName("verify_token");
Interceptor.attach(fn, {
  onEnter(args) {
    this.t0 = Date.now();
    this.tok = args[0].readUtf8String();
  },
  onLeave(retval) {
    send({ fn: "verify_token", len: String(this.tok).length, ret: retval.toInt32(),
           ms: Date.now() - this.t0 });
  }
});
```

**Why this matters:** Replacing return values across every export changes program behaviour and destroys the observation, and the wildcard makes attribution impossible. Hooking one export and emitting a structured record gives a line that can be tied to a user action, which is what a diagnostic trace is for.

## When It Is NOT This Issue

- **Hook fired on startup.** A hook that runs before any user action is library initialisation, not the behaviour under test.
- **Timing artefact read as failure.** Instrumentation slows the process; a timeout under instrumentation may not reproduce without it.
- **Anti-tamper detection.** A crash or silent exit immediately after attach is a protection, not a finding about the tested function.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `Java.perform` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `frida-diagnostic-tracing-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: frida-diagnostic-tracing-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `Java.perform`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile frida_diagnostic_tracing_scripting.py; python frida_diagnostic_tracing_scripting.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `frida-diagnostic-tracing-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-295`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
