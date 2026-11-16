---
name: ssti-node-and-client-engines
description: Node and client-side template injection. Covers EJS, Handlebars, Pug and client-side template injection where Angular or Vue expressions evaluate user input. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ejs ssti", "handlebars ssti", "pug ssti", "client side template injection", "angular injection"]
cwe: [CWE-1336, CWE-94]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [ssti, ssti-jinja2-and-twig, ssti-java-template-engines, ssti-sandbox-escape]
parent: ssti
---

# SSTI Node and Client Engines - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Node server engines (EJS, Handlebars, Pug) and client-side frameworks (Angular, Vue) compile a template into a JavaScript function, so when request data is concatenated into the template text, or lands inside a framework interpolation region, the expression is executed in the engine's scope. Server-side the break is at `ejs.render`, `Handlebars.compile`, or `pug.compile` receiving attacker source, and the attacker reaches `process`, `global`, and `constructor.constructor` to run code in the Node process. Client-side the break is that framework interpolation evaluates `{{ }}` against the scope, and because Angular removed its expression sandbox in 1.6 the evaluated expression reaches the browser JavaScript context (CSTI), yielding script execution without a classic `<script>` tag. The decision point is whether user data is bound to the template as data or becomes part of the template program.

- **Precondition chain:** Request data is compiled as template text by EJS, Handlebars, or Pug, or it lands inside a framework interpolation region in Angular or Vue, the engine evaluates it in a JavaScript scope, and no logic-less binding or CSP confines the result.
- **Readable differential:** Submit an interpolation that evaluates a benign expression (for example `<%= 7*7 %>` in EJS or `{{7*7}}` in Angular) versus the same text as data; a finding exists when the interpolation renders the product while the data form stays literal, and it closes once the value is bound through escaped data interpolation only.
- **Empirical grounding:** CWE-1336 and CWE-94 under OWASP Top 10:2025 A05:2025 Injection, with the client-side template injection (CSTI) variant where a framework interpolation evaluates attacker expressions. SOURCES.md lists no advisory specific to the Node or client engines, so this entry stays at the taxonomy level rather than asserting a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the engine is server-side EJS or Pug and `<%= 7*7 %>` or `#{7*7}` renders 49 **THEN** treat `process`, `global`, and `this.constructor.constructor` as the Node scope gateway and confirm the request reaches `ejs.render` or `pug.compile` as source
2. **IF** the engine is Handlebars **THEN** remember it is logic-less so arithmetic will not evaluate; probe raw `{{{ }}}` output and helper abuse and check whether `knownHelpersOnly` is set
3. **IF** the interpolation is evaluated in the browser by Angular or Vue **THEN** classify as client-side template injection and keep the proof in the DOM, checking whether a CSP blocks the resulting script
4. **IF** the target profile is not yet confirmed **THEN** start at parent class [`ssti`](../ssti/SKILL.md) (1 hop) for engine-agnostic polyglots
5. **IF** the engine is Python Jinja2 or PHP Twig **THEN** switch to [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) (1 hop)
6. **IF** the engine is a JVM template such as FreeMarker or Velocity **THEN** switch to [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) (1 hop)
7. **IF** a sandbox or restricted context is in place and OS execution is the aim **THEN** switch to [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) (1 hop)
8. **IF** the client-side expression only writes HTML the browser runs **THEN** treat the DOM execution path through [`cross-site-scripting`](../cross-site-scripting/SKILL.md) and confirm whether Trusted Types or CSP intervene
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** the value is only ever interpolated as escaped data and no region compiles it **THEN** STOP and classify as a verified non-finding for CWE-1336

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Client-side interpolation runs script in the victim browser | [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) | The invariant is browser DOM handling, not server template compilation |
| A framework merges attacker keys into an object prototype during binding | [`prototype-pollution`](../prototype-pollution/SKILL.md) | The break is prototype chain mutation, not expression evaluation |
| The value reaches `eval` or `new Function` directly | [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) | The sink is a raw evaluator with no template layer |
| Need parent class methodology | [`ssti`](../ssti/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find the compile call or the interpolation region.** Server-side grep for `ejs.render`, `Handlebars.compile`, `pug.compile`, or `res.render` built from a request field; client-side locate where attacker data lands inside an Angular or Vue `{{ }}` region or an `ng-bind`, `ng-bind-html`, or `v-html` directive.
2. **Identify the engine and its delimiter family.** EJS `<%= %>` and `<%- %>`, Pug `#{ }` and `!{ }`, Handlebars `{{ }}` and `{{{ }}}`, and framework `{{ }}` behave differently: Handlebars is logic-less so arithmetic never evaluates, while EJS and Angular do, which decides the probe.
3. **Record a paired baseline.** Submit a benign token and capture whether it is HTML-escaped, emitted raw, or evaluated, establishing the reflection mode before testing evaluation.
4. **Choose the branch from engine behavior.** For EJS or Pug test server-side arithmetic; for Handlebars test raw `{{{ }}}` output and helper resolution since arithmetic will not fire; for Angular or Vue test browser evaluation in the rendered DOM rather than the raw response.
5. **Separate server execution from browser execution.** A product in the raw HTTP response implies server compilation in the Node process; a product appearing only after the browser renders implies client-side template injection with a different impact and fix.
6. **Stop condition.** Halt when the probe (a) evaluates server-side or in the DOM and reverts to literal once bound as escaped data, (b) stays literal across two baselines, or (c) would require running a Node command or stealing a session to advance. Case (a) confirms, (b) is a non-finding, (c) is out of scope here.
7. **State what counts as proof.** Proof is the single-variable differential plus the location: `<%= 7*7 %>` returns `49` in the response while the literal does not and the source shows the request field inside `ejs.render`; for CSTI the expression runs in the DOM and is absent when bound through text interpolation.
8. **Close with the structural fix.** Never pass request data as template source: render static templates with data locals, set Handlebars `knownHelpersOnly: true` and avoid `{{{ }}}` for user data, keep Angular and Vue away from `ng-bind-html` and `v-html` on untrusted input, and enforce a CSP that blocks inline execution. Verify by replaying the evaluation probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `<%= 7*7 %>` or `#{7*7}` returning `49` in the HTTP response | Proves server-side compilation of attacker source by EJS or Pug inside the Node process |
| `{{{userValue}}}` emitting unescaped markup in a Handlebars view | Proves raw triple-stache output where the logic-less engine still bypasses escaping on that field |
| `{{constructor.constructor}}` resolving in an Angular or Vue expression | Proves client-side template injection reaching the browser JavaScript context after the framework sandbox was removed |
| `res.render` or `ejs.render` whose template argument is built from `req` data | Proves the source-level defect: user input is the template program, not the data |
| `ng-app`, `ng-bind`, or `v-html` wrapping a reflected parameter | Proves an interpolation region evaluates attacker input in the DOM on the Angular or Vue stack |
| A `Content-Security-Policy` absent or allowing `unsafe-eval` on a framework-rendered page | Proves the CSTI result is not confined by policy, raising the client-side impact |
| Handlebars compiled without `knownHelpersOnly` and a registered helper taking user input | Proves helper-level evaluation is reachable even though arithmetic is not |

## Worked Contrast

**Vulnerable pattern:**

```javascript
const ejs = require("ejs");

app.get("/card", (req, res) => {
  // Request value concatenated into the template source, so EJS compiles it
  const tpl = "<div class='card'>" + req.query.title + "</div>";
  res.send(ejs.render(tpl));
});
```

**Hardened pattern:**

```javascript
const ejs = require("ejs");
// Template is a fixed file; the request value is passed only as a data local
const cardTpl = ejs.compile(fs.readFileSync("views/card.ejs", "utf8"));

app.get("/card", (req, res) => {
  // <%= title %> in the file escapes and binds the value as data, never as source
  res.send(cardTpl({ title: req.query.title }));
});
```

**Why this matters:** The defect concatenates the request value into the EJS source, so the `<%= %>` the attacker supplies is compiled. The fix compiles a fixed template file once and passes the value only as a data local, so EJS escapes and binds it rather than compiling it.

## When It Is NOT This Issue

- **Handlebars arithmetic stays literal:** `{{7*7}}` rendering as `7*7` is expected because Handlebars is logic-less; absence of evaluation there is not proof of safety nor of a finding.
- **Escaped interpolation:** a value shown through `<%= %>` or `{{ }}` as HTML-escaped data is bound, not compiled; the engine never treats it as source.
- **Server reflection mistaken for CSTI:** a product that appears in the raw response is server-side SSTI, not client-side; do not file it as CSTI without browser evaluation.
- **Framework braces in a non-bootstrapped region:** `{{ }}` text outside any `ng-app` or Vue mount point is inert and never evaluated.
- **Trusted build-time templates:** `.ejs` or `.pug` files rendered only from server-controlled data with no request field in the source are out of scope.
- **CSP blocks the client execution:** an Angular expression that evaluates but whose resulting script is refused by a strict CSP has reduced impact; record the policy as the compensating control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssti-node-and-client-engines` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssti-node-and-client-engines` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssti-node-and-client-engines
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1336, CWE-94 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssti`](../ssti/SKILL.md) - Web and Application (core)
- [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) - Web and Application (leaf)
- [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) - Web and Application (leaf)
- [`ssti-sandbox-escape`](../ssti-sandbox-escape/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssti-node-and-client-engines` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1336, CWE-94, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | bugbounty-hunter-v1 (2), CYBER_CPT/hacktricks (2), CYBER_CPT/ctftime (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
