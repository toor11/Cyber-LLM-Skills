---
name: prototype-pollution-rce-chains
description: Prototype pollution to remote code execution. Covers reaching code execution through child_process options, template engines, and EJS or Handlebars gadgets polluted via server-side sinks. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["prototype pollution rce", "pp to rce", "node rce pollution"]
cwe: [CWE-1321]
owasp: [A08:2021]
attack: []
capec: [CAPEC-460]
related: [prototype-pollution, prototype-pollution-server-side, prototype-pollution-client-side-gadgets, sql-injection]
parent: prototype-pollution
---

# Prototype Pollution RCE Chains - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant escalates server-side pollution to code execution: once Object.prototype is polluted, a gadget reads the attacker-set key at a point that controls process spawning or template compilation. Classic chains set defaults that child_process spawn or exec options honor, such as shell, env, NODE_OPTIONS, or argv0, or that a template engine like EJS, Handlebars, or Pug reads as a compile option, such as outputFunctionName, compile, or client, so the rendered template emits attacker code. The security decision is the gadget that reads an unset option and passes it to an exec or compile call; pollution supplies the option the developer never set, and the attacker gains execution in the Node process.

- **Precondition chain:** a server-side pollution sink exists, a reachable gadget later reads an unset option that feeds child_process or a template compiler, the option is controllable through the polluted prototype, and the gadget path actually runs with the polluted default in place.
- **Readable differential:** trigger the polluting request then exercise the gadget route with a benign marker option versus none; execution is proven when the gadget behaves as if the attacker-set option were present, for example an inert env var or template token surfaces, and it stops when prototype keys are rejected.
- **Empirical grounding:** This maps to CWE-1321 under OWASP Top 10:2025 A08; SOURCES.md has no prototype-pollution-to-RCE advisory, so grounding stays at taxonomy, and the template-engine sandbox-escape advisories in SOURCES (such as the Jinja2 attr filter GHSA-cpwx-vrp4-4pq7 and the Grav Twig GHSA-662m-56v4-3r8f and GHSA-gjc5-8cfh-653x) concern server-side template injection, a sibling invariant not cited here.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to pollute server-side **THEN** start at parent class [`prototype-pollution`](../prototype-pollution/SKILL.md) (1 hop) to prove the write before chasing a gadget
2. **IF** a child_process call is made without an explicit options object **THEN** test an inert env or shell default that the spawn would inherit from the prototype
3. **IF** the app renders EJS templates with options read from a default **THEN** set an inert outputFunctionName and observe the compiled output change
4. **IF** Handlebars or Pug compiles with helpers or options from a default **THEN** probe the compile-option gadget specific to that engine and version
5. **IF** you have a pollution sink but no confirmed gadget **THEN** work sink-first by enumerating reachable spawn and compile call sites that omit explicit options
6. **IF** the chain overlaps with server-side template injection **THEN** switch to [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) (1 hop) when template content itself is attacker-built
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** pollution works but no gadget reaches spawn or compile **THEN** STOP and classify as pollution without an execution path

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Template content itself is built from attacker input | [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) | The invariant is template injection, not a polluted compile option |
| The gadget feeds an operating-system command | [`os-command-injection`](../os-command-injection/SKILL.md) | Impact is command execution through spawn, a distinct sink |
| The gadget reaches a dynamic eval of attacker data | [`code-injection-and-eval-dynamic-language-eval`](../code-injection-and-eval-dynamic-language-eval/SKILL.md) | Execution flows through eval rather than a spawned process |
| Need parent class methodology | [`prototype-pollution`](../prototype-pollution/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Confirm server-side pollution first with an inert canary, since without the write there is no chain.
2. Enumerate gadgets that read an unset option feeding child_process spawn or a template compile call.
3. Map which engine and version is present, because the exact option gadget differs across EJS, Handlebars, and Pug.
4. Choose the branch from evidence: a spawn without an explicit options object points at env or shell gadgets; a template compile reading a default points at compile-option gadgets.
5. Define the baseline-versus-probe differential: exercise the gadget route with no pollution versus with an inert option set through the prototype, and compare behaviour.
6. Set only an inert marker option, never a command, so the test proves the gadget without running a payload.
7. **Stop condition.** Stop when (a) the gadget honors the inert attacker-set option, for example a benign env var is echoed by a child or a template token renders, (b) pollution works but no gadget route executes, or (c) advancing would run a real command; (a) is confirmation, (b) is non-exploitable, (c) is out of scope.
8. **State what counts as proof.** Proof is the gadget emitting the attacker-set inert option and reverting once prototype keys are guarded, with no command executed. Close with guarding keys, passing explicit null-prototype options objects to spawn and compile, pinning a patched engine, and re-running the inert-option probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| child_process spawn or execFile called without an explicit options object | Proves an inheritable-option gadget on Node where prototype defaults become spawn options |
| EJS reading outputFunctionName or compile from an unset default | Proves a template compile gadget that can emit attacker-controlled output |
| A NODE_OPTIONS default read at spawn time | Proves an environment-injection gadget on the Node runtime |
| Handlebars compile reading helpers from a default | Proves a helper gadget specific to the templating engine |
| A polluted shell:true default reaching exec | Proves escalation from argument passing to shell interpretation |
| An inert env var surfacing in a spawned child | Proves the chain end to end without executing any payload |

## Worked Contrast

**Vulnerable pattern:**

```javascript
const { execFile } = require("child_process");
// No explicit options object: spawn reads defaults off the (pollutable) prototype.
app.post("/export", (req, res) => {
  deepMerge(settings, req.body);        // a pollution sink sets proto.shell or proto.env
  execFile("wkhtmltopdf", [settings.src, "/tmp/out.pdf"], (e) => res.end(e ? "err" : "ok"));
});
```

**Hardened pattern:**

```javascript
const { execFile } = require("child_process");
app.post("/export", (req, res) => {
  const clean = stripProtoKeys(req.body);          // __proto__ and constructor removed
  const opts = Object.assign(Object.create(null), { shell: false, env: {} });
  execFile("wkhtmltopdf", [String(clean.src || "")], opts, (e) => res.end(e ? "err" : "ok"));
});
```

**Why this matters:** The defect calls execFile with no options object, so a polluted Object.prototype.env or shell becomes the effective spawn option. The fix passes an explicit null-prototype options object with shell false and an empty env, so prototype defaults cannot influence the child process, and body keys are stripped before use.

## When It Is NOT This Issue

- **Explicit options objects:** spawn or compile calls that always pass an own options object ignore prototype defaults.
- **Patched template engine:** an EJS or Handlebars release that no longer reads tainted options closes the gadget.
- **Pollution with no gadget route:** a confirmed write that never reaches a spawn or compile path is not execution.
- **Frozen prototype:** a process that freezes Object.prototype blocks the option injection.
- **Null-prototype options built explicitly:** options created with Object.create(null) cannot inherit a polluted key.
- **Reflection mistaken for a chain:** an echoed pollution with no exec path is not RCE.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `prototype-pollution-rce-chains` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prototype-pollution-rce-chains` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: prototype-pollution-rce-chains
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1321 | Mapping: A08:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`prototype-pollution`](../prototype-pollution/SKILL.md) - Web and Application (core)
- [`prototype-pollution-server-side`](../prototype-pollution-server-side/SKILL.md) - Web and Application (leaf)
- [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prototype-pollution-rce-chains` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/go_exploitdb (3), CYBER_CPT/github_security_md (2), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
