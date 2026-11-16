---
name: ssti-sandbox-escape
description: Template sandbox escape. Covers escaping restricted template environments and sandboxes to reach OS execution, including attribute and class traversal patterns per engine. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ssti sandbox escape", "template sandbox", "ssti rce", "template escape"]
cwe: [CWE-1336, CWE-94]
owasp: [A03:2021]
attack: [T1190]
capec: [CAPEC-242]
related: [ssti, ssti-jinja2-and-twig, ssti-java-template-engines, ssti-node-and-client-engines]
parent: ssti
---

# SSTI Sandbox Escape - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A template sandbox such as the Jinja2 SandboxedEnvironment, a Twig SecurityPolicy, Thymeleaf expression restrictions, or a Grav safe-filter allowlist permits expression evaluation but tries to deny the attribute and callable access that reaches OS primitives. A sandbox escape is a gadget the allowlist overlooked: a permitted attribute or filter that transitively returns an object whose own methods are not re-checked. GHSA-cpwx-vrp4-4pq7 is the canonical case where the Jinja2 `|attr` filter reaches `str.format` and walks to module globals; the April 2025 Thymeleaf research chains `th:with` and `#ctx` to the TemplateManager; Grav's bypass in GHSA-gjc5-8cfh-653x defeats `cleanDangerousTwig` and `system.twig.safe_filters`; and GHSA-7rmm-689c-gjgv reaches Xibo module template RCE. The security decision is whether the sandbox mediates every transitive attribute access or only the first hop, and the attacker gains code or command execution inside the rendering process.

- **Precondition chain:** A sandbox or restricted template context evaluates attacker expressions, at least one permitted attribute, filter, or function transitively returns an unmediated callable, and that callable reaches an OS or reflection primitive.
- **Readable differential:** Compare a permitted first-hop expression that the sandbox allows against the same expression extended one hop to a transitively reachable callable; a finding exists when the extended chain returns an object the sandbox was meant to forbid, and it is closed when the sandbox mediates that second hop or the engine is patched past the advisory.
- **Empirical grounding:** CWE-1336 and CWE-94 under OWASP Top 10:2025 A05:2025 Injection. GHSA-cpwx-vrp4-4pq7 is the Jinja2 `|attr` to `str.format` SandboxedEnvironment escape; the April 2025 Thymeleaf research chains `th:with` and `#ctx` to the TemplateManager; GHSA-gjc5-8cfh-653x is the Grav Twig safe-filter bypass; and GHSA-7rmm-689c-gjgv is the Xibo CMS Twig module RCE fixed in 4.3.1.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a Jinja2 SandboxedEnvironment is in place **THEN** probe the `|attr` filter and `str.format` chain from GHSA-cpwx-vrp4-4pq7 to see whether the second attribute hop is mediated
2. **IF** a Twig SecurityPolicy or Grav safe-filter allowlist is in place **THEN** test the `cleanDangerousTwig` and `system.twig.safe_filters` bypass surface of GHSA-gjc5-8cfh-653x
3. **IF** the engine is Thymeleaf with expression restrictions **THEN** chain `th:with` and `#ctx` toward the TemplateManager as the April 2025 research describes
4. **IF** the engine is a JVM template such as FreeMarker or Velocity **THEN** switch to [`ssti-java-template-engines`](../ssti-java-template-engines/SKILL.md) (1 hop)
5. **IF** the engine is EJS, Handlebars, Pug, or a client framework **THEN** switch to [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) (1 hop)
6. **IF** the engine is Jinja2 or Twig but no sandbox is configured at all **THEN** switch to [`ssti-jinja2-and-twig`](../ssti-jinja2-and-twig/SKILL.md) (1 hop) because there is no boundary to escape
7. **IF** the target profile is not yet confirmed **THEN** start at parent class [`ssti`](../ssti/SKILL.md) (1 hop)
8. **IF** expression evaluation works but every escape gadget is mediated **THEN** record expression evaluation only and drive patching rather than claiming RCE
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** no transitive callable escapes the allowlist after enumeration **THEN** STOP and classify as a contained sandbox, a verified non-finding for escape

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Escape reaches an OS command or process spawn | [`code-injection-and-eval-expression-language`](../code-injection-and-eval-expression-language/SKILL.md) | Outside the sandbox the invariant becomes arbitrary expression evaluation, not template containment |
| The reachable gadget is a serialization gadget chain | [`insecure-deserialization-python-and-ruby-gadgets`](../insecure-deserialization-python-and-ruby-gadgets/SKILL.md) | The primitive is object-graph reconstruction, a distinct sink from attribute traversal |
| The escaped callable runs a shell command directly | [`os-command-injection-escalation-to-shell`](../os-command-injection-escalation-to-shell/SKILL.md) | The final invariant is OS command construction, handled by that skill |
| Need parent class methodology | [`ssti`](../ssti/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm a sandbox exists and enumerate its allowlist.** Determine whether the engine runs a Jinja2 SandboxedEnvironment, a Twig SecurityPolicy, Thymeleaf expression restrictions, or a Grav safe-filter list, and record which attributes, filters, tags, and functions it permits versus rejects with a SecurityError.
2. **Map the first-hop permitted objects.** List the objects the allowlist hands you directly: loop `cycler`, `self`, the `|attr` filter, Twig `_self`, or Thymeleaf `#ctx`. These are the roots of any escape chain.
3. **Record a mediation baseline.** Capture the sandbox response to a forbidden first hop, a SecurityError or empty render, so that a later success is attributable to a missed second hop and not to the sandbox being absent.
4. **Extend each permitted root by one transitive hop.** Follow a permitted attribute to an object whose own methods the sandbox never re-checks: `|attr('__class__')` toward `str.format` per GHSA-cpwx-vrp4-4pq7, `th:with` into `#ctx` toward the TemplateManager, or a Twig filter the Grav allowlist cleared in GHSA-gjc5-8cfh-653x.
5. **Decide the branch from where mediation stops.** If the first hop is blocked but the second hop through a permitted object succeeds, the sandbox mediates only one level and the escape is real; if every transitive hop is re-checked, the boundary holds.
6. **Stop condition.** Halt when the chain either (a) returns an object the allowlist forbids and is re-blocked on a patched engine, (b) is rejected at every hop across the enumeration, or (c) would require running a real OS command to continue. Case (a) confirms the escape, (b) is a contained sandbox, (c) is out of scope.
7. **State what counts as proof.** Proof is a mediation differential: a forbidden primitive is unreachable directly yet reachable through a permitted gadget hop, with the gadget named (for example `|attr` to `str.format`), and the chain re-blocked on a build past GHSA-cpwx-vrp4-4pq7 or GHSA-7rmm-689c-gjgv. Reaching `__globals__` in a non-sandboxed engine is plain SSTI, not an escape.
8. **Close with the structural fix.** Stop rendering untrusted templates; where dynamic templates are mandatory upgrade past the advisory, treat the sandbox as defense in depth rather than a trust boundary, and move rendering into an isolated process with no filesystem or network. Verify by replaying the gadget chain against the patched, isolated build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `attr` filter succeeding where dotted `__class__` is blocked | Proves the Jinja2 sandbox mediates only direct attribute access, the GHSA-cpwx-vrp4-4pq7 gadget on the Python stack |
| A permitted Twig filter returning an object whose methods are unchecked | Proves the Grav safe-filter allowlist of GHSA-gjc5-8cfh-653x is bypassable one hop deep on the PHP stack |
| `#ctx` reachable via `th:with` in a Thymeleaf expression | Proves the Thymeleaf restriction chain toward the TemplateManager described in the April 2025 research |
| A SecurityError on a direct primitive but a clean render through a gadget | Proves single-level mediation: the boundary exists but does not follow transitive references |
| `str.format` or `format_map` reachable from a sandboxed value | Proves a format-string gadget that walks to module globals without a banned attribute name |
| Engine version string predating the advisory fix in a dependency manifest | Proves the known escape is unpatched, corroborating the runtime differential on Jinja2, Twig, or Xibo |
| Rendering worker able to open files or sockets during template evaluation | Proves the sandbox is not process-isolated, so a single gadget yields full process capability |

## Worked Contrast

**Vulnerable pattern:**

```python
from jinja2.sandbox import SandboxedEnvironment

# Treats the sandbox as a trust boundary and compiles attacker source
env = SandboxedEnvironment()

def render_note(note_source):
    # A permitted filter like |attr can still reach str.format and escape
    return env.from_string(note_source).render()
```

**Hardened pattern:**

```python
from jinja2 import Environment, FileSystemLoader, select_autoescape

# Attacker data is never template source; only fixed files are compiled
env = Environment(loader=FileSystemLoader("templates"),
                  autoescape=select_autoescape())

def render_note(note_text):
    # The note is bound as a context variable, so no gadget chain can start
    return env.get_template("note.html").render(note=note_text)
```

**Why this matters:** The defect compiles attacker-supplied source and relies on the sandbox as a boundary, which GHSA-cpwx-vrp4-4pq7 shows is escapable through `|attr`. The fix removes untrusted source entirely: a fixed template file is compiled and the note is bound as data, so there is no expression for a gadget chain to start from.

## When It Is NOT This Issue

- **No sandbox means no escape:** reaching `__globals__` in a plain `from_string` with no SandboxedEnvironment is ordinary SSTI; file it as the engine skill, not as a sandbox escape.
- **SecurityError at every hop:** a sandbox that rejects the gadget chain with a SecurityError on a patched engine is holding; expression evaluation alone is reduced severity.
- **Forbidden-name blocklist mistaken for a sandbox:** a regex that strips `__class__` is not the engine sandbox, and its bypass is a filter-evasion finding, not an engine escape.
- **Build-time rendering:** templates compiled from trusted repository content never expose an attacker-controlled expression to escape.
- **Patched engine, archived PoC:** a gadget from an advisory that no longer reproduces on the installed version is historical; require a live mediation differential.
- **Process already isolated:** an escape that lands in a throwaway container with no filesystem, network, or secrets has no onward impact; record the isolation as the control.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssti-sandbox-escape` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssti-sandbox-escape` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssti-sandbox-escape
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
- [`ssti-node-and-client-engines`](../ssti-node-and-client-engines/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssti-sandbox-escape` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1336, CWE-94, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/hacker_recipes (3), CYBER_CPT/gh_advisories (2), hackerone_disclosed_reports (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
