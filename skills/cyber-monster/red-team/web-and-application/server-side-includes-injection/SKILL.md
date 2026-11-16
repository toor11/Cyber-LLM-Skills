---
name: server-side-includes-injection
description: Exploits SSI injection to read files and execute commands where .shtml or SSI-enabled handlers process user input, including echo, exec and include directives. Use when the target serves SSI-processed pages or accepts input in included files.
family: web-and-application
tier: leaf
triggers: ["ssi injection", "server side includes", "shtml injection", "ssi directives"]
cwe: [CWE-97]
owasp: [A03:2021]
attack: []
capec: [CAPEC-101]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Server Side Includes Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Server-side include directives are evaluated by the web server when a page served through an SSI-enabled handler is assembled, so if user input is written into such a page without neutralisation, sequences beginning with the comment-and-hash opener are interpreted as directives. An echo directive resolves a server variable, an include directive reads a file by virtual or file path, and an exec directive runs a command when the handler permits it. The security decision is whether attacker bytes reach the include parser unescaped and whether the directory carries Options with Includes and without IncludesNOEXEC. Because the parse happens at response generation, both reflected input and stored input rendered later reach the same sink, and the attacker gains variable disclosure, server-side file read, or command evaluation.

- **Precondition chain:** a response is processed by an SSI-enabled handler, user-controlled input is written into that response without neutralising the comment-and-hash directive opener, and the handler's Options permit Includes and, for command evaluation, omit the NOEXEC modifier.
- **Readable differential:** a benign literal containing directive-looking but encoded text versus a live directive such as an echo of a known server variable; the finding exists when the live directive resolves its value while the encoded literal renders as text, and it reverts when the directive characters are HTML-encoded before the page is parsed.
- **Empirical grounding:** CWE-97 (improper neutralisation of server-side includes) sits under OWASP Top 10:2025 A05:2025 Injection, the taxonomy anchor for directive execution in server-parsed pages.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the page is served with a .shtml, .shtm, or .stm extension or an SSI output filter **THEN** confirm the handler actually parses includes before probing, otherwise directives render as text
2. **IF** user input is reflected into an SSI-parsed page **THEN** test a benign echo of a server variable as a differential against the encoded literal
3. **IF** user input is stored and later rendered through an SSI page **THEN** treat it as stored SSI and locate the rendering path, which may differ from the input point
4. **IF** the handler is configured with Options IncludesNOEXEC **THEN** scope the finding to file read and variable disclosure, not command evaluation
5. **IF** the handler permits the exec directive **THEN** treat command evaluation as in scope but prove it with a benign echo of a literal, not a real command
6. **IF** the directive is an include of a remote or absolute path **THEN** this overlaps path handling; also read [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md)
7. **IF** the apparent SSI is really a template engine such as Jinja or Twig **THEN** switch to [`ssti`](../ssti/SKILL.md) (1 hop) because the grammar and sandbox differ
8. **IF** the exec directive is really OS command composition in application code **THEN** switch to [`os-command-injection`](../os-command-injection/SKILL.md) (1 hop)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** the handler does not parse includes or input is HTML-encoded before parsing **THEN** STOP and classify as a verified non-finding for CWE-97

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The directive executes a shell command | [`os-command-injection`](../os-command-injection/SKILL.md) | Once exec runs, the invariant is OS command neutralisation rather than SSI parsing |
| The payload is interpreted by a template engine instead | [`ssti`](../ssti/SKILL.md) | Template expression evaluation has a different grammar and sandbox than SSI directives |
| The include reads an arbitrary file path | [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) | File disclosure through an include is a path-canonicalisation invariant |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the handler actually parses includes.** Check the extension mapping and server configuration, such as AddOutputFilter INCLUDES and Options with Includes, so you are testing a real SSI sink rather than inert text.
2. **Locate where user input lands in the parsed page.** Distinguish reflected input in the same response from stored input rendered later through an SSI template, and note the exact field.
3. **Baseline with an encoded literal.** Submit text that merely looks like a directive, with the opener HTML-encoded, and record that it renders verbatim with no evaluation.
4. **Define the baseline-versus-probe differential.** Submit a harmless live directive such as an echo of a known server variable and compare the rendered output against the encoded baseline.
5. **Branch on the handler's capability.** If echo and include evaluate but exec is disabled, keep to variable and file-read evidence; only if the configuration shows exec enabled is command evaluation in scope, proven by a benign echo of a literal rather than a command.
6. **Stop condition.** Stop when (a) the live directive evaluates while the encoded literal does not, (b) both render as text identically, or (c) advancing would require running a real command or reading a sensitive file. Case (a) confirms CWE-97, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable differential, an encoded directive that stays text versus a live directive whose server variable resolves, plus the response showing the resolved value and the configuration line that enables Includes. A reflected string that never evaluates is not proof.
8. **Close with the structural fix.** HTML-encode the comment-and-hash opener before content reaches the include parser, set IncludesNOEXEC or disable the INCLUDES filter on user-influenced pages, and render untrusted data through a non-parsed content type; verify by replaying the directive probe against the patched page.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A response served by a handler with Options including Includes on a path that reflects user input | Proves the SSI parser is reachable with attacker bytes on Apache mod_include and IIS server-side-include stacks |
| An echo directive rendering a resolved value instead of literal text | Proves directive evaluation and environment disclosure on any SSI-enabled server |
| An include directive returning file contents inside the page | Proves server-side file read through the include parser; mod_include file inclusion |
| Options with Includes but without the IncludesNOEXEC modifier on the directory | Proves the exec directive is permitted, raising impact to command evaluation on Apache configurations |
| Stored input rendered through a .shtml template on a later request | Proves second-order SSI where input-time filtering is bypassed; template-backed SSI pages |
| User data written into a page whose output filter is INCLUDES | Proves the neutralisation gap is in output assembly rather than input validation; reverse-proxied SSI |

## Worked Contrast

**Vulnerable pattern:**

```python
def render_profile(bio, template_path="/var/www/profile.shtml"):
    # bio is written raw into a page the server parses for SSI directives,
    # so a directive inside bio is evaluated at response time.
    page = open(template_path).read().replace("{{bio}}", bio)
    open("/var/www/out/profile.shtml", "w").write(page)
    return "/out/profile.shtml"
```

**Hardened pattern:**

```python
import html

SSI_HANDLERS = (".shtml", ".shtm", ".stm")

def render_profile(bio, template_path="/var/www/profile.html"):
    # Encode the directive-forming characters and render to a non-parsed
    # extension so the include filter never sees attacker bytes.
    safe = html.escape(bio).replace("#", "&#35;")
    assert not template_path.endswith(SSI_HANDLERS)
    page = open(template_path).read().replace("{{bio}}", safe)
    out = "/var/www/out/profile.html"
    open(out, "w").write(page)
    return "/out/profile.html"
```

**Why this matters:** The hardened version HTML-encodes the comment and hash characters that begin a directive and writes to a non-parsed .html page, so user bytes cannot reach the SSI parser. Neutralisation happens at output assembly and the exec surface is removed by serving a content type the include filter does not process.

## When It Is NOT This Issue

- **Directive rendered as visible text:** if an echo directive appears literally in the page source and never resolves, the handler is not parsing includes and there is no finding.
- **Static .html with no INCLUDES filter:** a page whose extension and configuration exclude SSI processing cannot evaluate directives regardless of input.
- **IncludesNOEXEC set:** echo and include may work while exec is disabled, so command-evaluation claims are false and the finding is scoped to disclosure.
- **Template engine mistaken for SSI:** a brace or dollar expression evaluating is template injection, a different grammar, and should not be reported as SSI.
- **WAF strips the comment syntax:** a gateway that removes the directive opener before the origin means the probe never reached the parser, which is a control rather than proof of a safe backend.
- **Reflected in a JSON or attachment response:** content served with a type the SSI filter ignores does not evaluate directives.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `server-side-includes-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `server-side-includes-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: server-side-includes-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-97 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `server-side-includes-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-97`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 10 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/go_exploitdb (5), OffsecCyber (2), SecEval/owasp_wstg (1), SecEval/cwe (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
