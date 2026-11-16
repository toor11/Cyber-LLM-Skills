---
name: ssti
description: Exploits server-side template injection across Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble and ERB, from detection polyglots to sandbox escape and RCE. Use when user input is rendered by a template engine or when reflected input evaluates arithmetic.
family: web-and-application
tier: core
triggers: ["ssti", "template injection", "server-side template", "jinja2", "twig", "freemarker", "velocity"]
cwe: [CWE-1336, CWE-94]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [ssti-jinja2-and-twig, ssti-java-template-engines, ssti-sandbox-escape, sql-injection]
---

# SSTI - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Server-side template injection happens when user input becomes part of the template source the engine compiles, not merely a value passed into a precompiled template. Because template languages are expression languages, the engine evaluates attacker text as code: Jinja2 and Twig use `{{ }}`, Freemarker uses `${ }`, Velocity uses `#{ }` and `#set`, and ERB uses `<%= %>`. Detection starts with an arithmetic probe such as `{{7*7}}` rendering as 49, which proves evaluation rather than reflection. From evaluation an attacker walks the object graph to reach callables; the Jinja2 case GHSA-cpwx-vrp4-4pq7 shows an attribute filter reaching a plain `str.format` method to climb out of the sandbox. The invariant is that template content must never be assembled from request data, and a sandbox only reduces the reachable surface rather than removing the consequence.

- **Precondition chain:** Request data is concatenated into the template source rather than passed as a context variable, the engine evaluates that source, and the rendered output or a side effect reveals that evaluation occurred.
- **Readable differential:** A payload that forces evaluation such as `{{7*7}}` versus the same characters as inert text; a finding exists when the engine returns the computed value while a non-evaluating control returns the literal, and it closes when input is passed only as bound context into a fixed template.
- **Empirical grounding:** CWE-1336 and CWE-94 under OWASP A03:2021 Injection; GHSA-cpwx-vrp4-4pq7 shows a Jinja2 `|attr` filter reaching `str.format` to break the sandbox, and GHSA-7rmm-689c-gjgv shows Twig module template RCE in Xibo CMS, both confirming that a sandbox reduces but does not remove the consequence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target uses Jinja2 or Twig delimiters **THEN** switch to [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) (1 hop)
2. **IF** the target uses a Java engine such as Freemarker, Velocity, Pebble, or Thymeleaf **THEN** switch to [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) (1 hop)
3. **IF** a sandbox is present and must be escaped **THEN** switch to [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) (1 hop)
4. **IF** the engine is a Node or client-side templater **THEN** switch to [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) (1 hop)
5. **IF** an arithmetic probe renders as its product **THEN** treat evaluation as confirmed and identify the engine from the delimiter that fired
6. **IF** the input is reflected but never evaluated **THEN** reclassify as [`cross-site-scripting`](../cross-site-scripting/SKILL.md); reflection is not evaluation
7. **IF** the expression language is Spring EL or OGNL outside a template **THEN** read [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) for the expression path
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** no delimiter evaluates after testing each engine **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Input is reflected but not evaluated | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | The invariant is output encoding, not template evaluation |
| Evaluation is Spring EL or OGNL outside a template | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | The sink is an expression evaluator, a different surface |
| A Java template engine is confirmed | [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) | Delimiters and sandbox model are engine-specific |
| Target matches `ssti-jinja2-and-twig` | [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ssti-sandbox-escape` | [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ssti-node-and-client-engines` | [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find where input meets the template.** Separate input passed as a context variable into a precompiled template, which is safe, from input concatenated into the template source or handed to a string-render API, which is the sink.
2. **Confirm evaluation, not reflection.** Send an arithmetic probe in each candidate delimiter such as `{{7*7}}`, `${7*7}`, `#{7*7}`, and `<%= 7*7 %>` and look for the product; a returned 49 proves the engine evaluated, while the literal text proves mere reflection.
3. **Fingerprint the engine from which delimiter fired.** The delimiter that computes identifies Jinja2 or Twig versus Freemarker versus Velocity versus ERB, which selects the child skill and the correct object-graph vocabulary.
4. **Record a paired baseline.** Compare the evaluating probe against a non-evaluating control with the same characters neutralised, so the differential is evaluation and nothing else.
5. **Assess the sandbox, not just the escape.** Determine whether the engine runs a sandbox and remember it only narrows reach; GHSA-cpwx-vrp4-4pq7 reached `str.format` through an attribute filter, so sandbox presence does not close the finding.
6. **Stop condition.** Halt when a probe returns a computed value that reverts to literal when input is bound as context, or returns only the literal across engines, or would require invoking a system call to advance. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is an arithmetic or string-method expression evaluated by the engine on an otherwise identical request, plus the source line that concatenates input into the template or calls a string-render API. A reflected payload that is not computed is not proof.
8. **Close with the structural fix.** Render only fixed templates and pass request data exclusively as bound context, never compiling request strings; if user-authored templates are a product requirement, use a logic-less engine and treat the sandbox as defence in depth. Verify by re-running the arithmetic probe against the patched render path.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `{{7*7}}` rendering as 49 in the response | Proves the engine evaluated input on a Jinja2 or Twig stack, the canonical evaluation signal |
| `${7*7}` computing in the output | Proves a Freemarker or similar `${ }` engine evaluated the expression on a Java stack |
| `<%= 7*7 %>` producing 49 | Proves an ERB-style engine evaluated embedded Ruby, identifying the engine family |
| An attr filter reaching `str.format` as in GHSA-cpwx-vrp4-4pq7 | Proves a Jinja2 sandbox escape via a plain format method, showing a sandbox only narrows reach |
| `__class__.__mro__` or `config.__class__` walked from a template | Proves object-graph traversal toward callables in a Python template context |
| A string-render API compiling request data | Proves template content assembled from input, the broken invariant for this class |
| The same characters returned literally when passed as context | Proves the non-evaluating control, separating evaluation from reflection |

## Worked Contrast

**Vulnerable pattern:**

```python
from flask import request, render_template_string

def greet():
    name = request.args.get("name", "guest")
    # Request data is concatenated into the template source, so it is compiled as code
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)
```

**Hardened pattern:**

```python
from flask import request, render_template

def greet():
    name = request.args.get("name", "guest")
    # Fixed template file; input is passed only as bound context, never compiled
    return render_template("greet.html", name=name)
```

**Why this matters:** The defect builds the template source from request data and compiles it, so `{{7*7}}` and object-graph walks evaluate. The fix renders a fixed template and passes the value as a context variable the engine auto-escapes and never treats as template code; a sandbox would only narrow reach, so removing the string compilation is the real control.

## When It Is NOT This Issue

- **Reflection without evaluation:** a payload echoed verbatim is XSS territory; only a computed result such as 49 from 7*7 indicates evaluation.
- **Arithmetic in a client-side framework:** a front-end templater computing in the browser is client-side template injection, not server-side.
- **Context variable, not source:** input passed as a bound variable into a precompiled template is auto-escaped and does not compile.
- **Sandbox assumed to be a fix:** a sandbox narrows reach but has been escaped per GHSA-cpwx-vrp4-4pq7, so the presence of a sandbox is not a non-finding.
- **Static template with literal braces:** `{{` in static content the engine does not evaluate at that position is not injection.
- **Expression language outside templating:** SpEL or OGNL evaluated by a non-template sink belongs to code-injection, not this skill.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssti` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssti` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssti
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1336, CWE-94 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) - Web and Application (leaf)
- [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) - Web and Application (leaf)
- [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssti` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1336, CWE-94, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 62 |
| Distinct dataset sources | 12 |
| Top sources | OffsecCyber (32), hackerone_disclosed_reports (7), CYBER_CPT/ctf_search (5), CYBER_CPT/L5/ctf_search (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
