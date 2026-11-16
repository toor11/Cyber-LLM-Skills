---
name: ssti-jinja2-and-twig
description: "Jinja2 and Twig template injection. Covers Python and PHP template engines: detection polyglots, config and globals access, sandbox escape through MRO traversal, and Twig filter chains. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: web-and-application
tier: leaf
triggers: ["jinja2 ssti", "twig ssti", "python template injection", "php template injection"]
cwe: [CWE-1336, CWE-94]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [ssti, ssti-java-template-engines, ssti-sandbox-escape, ssti-node-and-client-engines]
parent: ssti
---

# SSTI Jinja2 and Twig - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Jinja2 (Python) and Twig (PHP) compile a template string into executable code, so when a request value is concatenated into the template source instead of passed as a bound context variable, the expression inside `{{ ... }}` and the statement inside `{% ... %}` are evaluated by the engine rather than printed. The security decision is whether the string is treated as data bound to a context or as template source handed to the compiler. In Jinja2 the gateway into the object graph is attribute and filter access such as `|attr` and `__class__`, which GHSA-cpwx-vrp4-4pq7 showed can reach `str.format` and escape the SandboxedEnvironment; in Twig the equivalent gateway is `_self`, `_context`, and filter chains. The attacker gains the ability to dump engine globals, read configuration and secrets, and on an unsandboxed engine reach code execution inside the rendering process.

- **Precondition chain:** A request value is concatenated into the template source rather than passed as a bound context variable, the engine compiles that source at request time, and either no sandbox is configured or the configured sandbox has a reachable gadget.
- **Readable differential:** Send a context expression such as `{{7*7}}` versus the literal text `7*7`; a finding exists when the response renders the evaluated product rather than the literal, and it disappears once the value is passed as a bound variable instead of spliced into the template.
- **Empirical grounding:** CWE-1336 and CWE-94, filed under OWASP Top 10:2025 A05:2025 Injection. GHSA-cpwx-vrp4-4pq7 is the Jinja2 `|attr` filter reaching `str.format` to break the SandboxedEnvironment (affected <= 3.1.5); GHSA-gjc5-8cfh-653x and GHSA-662m-56v4-3r8f are Grav Twig sandbox bypasses via `cleanDangerousTwig` and `system.twig.safe_filters`, and GHSA-7rmm-689c-gjgv is the Xibo CMS Twig module template RCE fixed in 4.3.1.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the engine is Python Jinja2 and `{{7*7}}` renders 49 **THEN** treat `|attr`, `__class__`, and `cycler.__init__.__globals__` as the object-graph gateway and check whether a SandboxedEnvironment is configured
2. **IF** the engine is PHP Twig and `{{7*7}}` renders 49 **THEN** pivot the probe to `_self`, `_context`, and filter chains and read whether a Twig SecurityPolicy restricts tags and filters
3. **IF** the target profile is not yet confirmed as Jinja2 or Twig **THEN** start at parent class [`ssti`](../ssti/SKILL.md) (1 hop) for engine-agnostic detection polyglots
4. **IF** the engine is EJS, Handlebars, Pug, or a client-side Angular or Vue expression **THEN** switch to [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) (1 hop)
5. **IF** the engine is FreeMarker, Velocity, or another JVM template **THEN** switch to [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) (1 hop)
6. **IF** a SandboxedEnvironment or Twig SecurityPolicy is present and the aim is OS execution through it **THEN** switch to [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) (1 hop)
7. **IF** the engine auto-escapes output but the value still lands inside the template source **THEN** classify as SSTI not XSS because the break is at compile time, and keep the differential on evaluation rather than on markup
8. **IF** only the evaluated value reflects and no globals or config are reachable **THEN** record expression evaluation as the finding and drive the structural fix before probing the object graph
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** the value is HTML-encoded and never compiled as template source **THEN** STOP and classify as a verified non-finding for CWE-1336 rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Value is evaluated by `eval` or `new Function` outside any template engine | [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) | The sink is a language evaluator, not a template compiler, so the fix is removing dynamic eval rather than sandboxing a template |
| Evaluated output is reflected into HTML and executes in the browser | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | The break is client-side rendering, a different layer than server-side compilation |
| The reachable gadget leads to OS execution through the engine | [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) | The invariant shifts from expression evaluation to sandbox containment |
| Need parent class methodology | [`ssti`](../ssti/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate where the request value enters the template.** Read the view layer for `render_template_string`, `Template(...)`, `Environment().from_string`, or Twig `createTemplate`, and find any place a request field is concatenated into template source rather than passed through the context dict or array.
2. **Classify the engine and its delimiter family.** Confirm Jinja2 or Twig from the stack, the `Content-Type`, and framework fingerprints, because the object-graph gateway differs: `|attr` and `__class__` for Jinja2, `_self` and filter chains for Twig.
3. **Record a paired baseline.** Submit a plain literal such as `canary7x7` and capture status, length, and the reflected bytes, so the rendered-value comparison has a noise floor.
4. **Choose the branch from what renders.** If an arithmetic expression inside the delimiters returns its product, the string is being compiled; if it returns verbatim, the value is bound data and this is not SSTI. Pick Jinja2 attribute traversal or Twig `_self` probing based on the engine identified earlier.
5. **Escalate one capability layer at a time.** Expression evaluation first, then read-only globals (`config`, `_context`), then whether a SandboxedEnvironment or Twig SecurityPolicy intercepts attribute access. Halt at the first layer that proves source compilation; deeper layers change impact, not the finding.
6. **Stop condition.** Halt when the probe either (a) renders an evaluated expression that reverts to literal once the value is passed as a bound variable, (b) renders the literal across two baselines so no compilation occurs, or (c) would require executing an OS command to advance. Case (a) is confirmation, (b) a non-finding, (c) belongs to `ssti-sandbox-escape`.
7. **State what counts as proof.** Proof is a single-variable differential: the identical request with `{{7*7}}` yields `49` while the literal yields `7*7`, plus the source line where the request field is concatenated into the template. A 500 error naming the template engine is not proof on its own.
8. **Close with the structural fix.** Pass the value only as a bound context variable, never into the template source; keep templates on disk as static files; where dynamic templates are unavoidable enable the engine sandbox and patch past GHSA-cpwx-vrp4-4pq7. Verify by replaying the `{{7*7}}` pair against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `{{7*7}}` rendering as `49` in the response body | Proves the request value is compiled as template source on Jinja2 or Twig, not bound as context data |
| `{{config.items()}}` or `{{config}}` returning application settings | Proves read access to Flask and Jinja2 globals including SECRET_KEY, which is config disclosure before any RCE on the Python stack |
| `attr` filter or `__class__.__mro__` surviving the sandbox | Proves the Jinja2 SandboxedEnvironment gateway of GHSA-cpwx-vrp4-4pq7 is reachable through the attr filter |
| `{{_self}}` or `{{_context}}` resolving in a Twig response | Proves Twig is compiling attacker source and exposes the environment handle on the PHP stack |
| A Twig `system.twig.safe_filters` or `cleanDangerousTwig` configuration entry | Proves a Grav-style filter allowlist is the only barrier, the exact surface of GHSA-gjc5-8cfh-653x |
| `render_template_string` or `Environment.from_string` fed a request field | Proves the defect at the source level: user input reaches the compiler independent of runtime reflection |
| `{% ... %}` statement tags accepted and executed in the response | Proves statement-level control, a stronger primitive than expression-only evaluation on either engine |

## Worked Contrast

**Vulnerable pattern:**

```python
from flask import request, render_template_string

def greeting():
    name = request.args.get("name", "")
    # Request value concatenated into the template source, so it is compiled
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
```

**Hardened pattern:**

```python
from flask import request, render_template

def greeting():
    name = request.args.get("name", "")
    # Value passed as a bound context variable; the template is a static file
    # Jinja2 autoescaping treats {{ name }} as data, never as source
    return render_template("greeting.html", name=name)
```

**Why this matters:** The defect splices the request value into the template string, so the engine compiles the `{{...}}` the attacker supplies. The fix keeps the template as a fixed on-disk file and passes the value only through the context, so the engine binds it as data and never compiles attacker input.

## When It Is NOT This Issue

- **Reflected but never compiled:** `{{7*7}}` appears in the response as literal `7*7` because the value is HTML-escaped output, not template source. That is at most reflected XSS, a different layer.
- **Bound context variable:** the value reaches `render_template(..., name=value)` and shows inside `{{ name }}` as data; the engine never compiles it, so arithmetic probes return verbatim.
- **Client-side framework braces:** `{{ }}` evaluated in the browser by Angular or Vue is client-side template injection; route it to the node-and-client engines skill rather than reporting server-side SSTI.
- **Engine 500 with no evaluation:** a template syntax error returning a stack trace proves the parser was reached, not that attacker expressions evaluate; require a rendered product.
- **Sandbox holds across every gadget:** a SandboxedEnvironment or Twig SecurityPolicy that rejects `__class__`, `|attr`, and `_self` with a SecurityError means evaluation exists but containment is intact; report at reduced severity.
- **Static site generator at build time:** templates compiled from trusted repository content at build time, never from request data, are out of scope even where `{{ }}` syntax is everywhere.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssti-jinja2-and-twig` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssti-jinja2-and-twig` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssti-jinja2-and-twig
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1336, CWE-94 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssti`](../ssti/SKILL.md) - Web and Application (core)
- [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) - Web and Application (leaf)
- [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) - Web and Application (leaf)
- [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssti-jinja2-and-twig` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1336, CWE-94, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/hacktricks (6), CYBER_CPT/secwiki (3), CYBER_CPT/osv (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
