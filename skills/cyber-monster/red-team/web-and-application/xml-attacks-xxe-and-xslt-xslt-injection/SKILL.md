---
name: xml-attacks-xxe-and-xslt-xslt-injection
description: XSLT injection and extension abuse. Covers injecting into XSLT stylesheets, reaching extension functions for file read and execution, and engine-specific capabilities. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["xslt injection", "xsl extension", "xslt rce", "stylesheet injection"]
cwe: [CWE-611, CWE-643]
owasp: [A05:2021]
attack: []
capec: [CAPEC-221]
related: [xml-attacks-xxe-and-xslt, xml-attacks-xxe-and-xslt-xpath-and-schema, sql-injection, cross-site-scripting]
parent: xml-attacks-xxe-and-xslt
---

# Xml Attacks XXE and Xslt Xslt Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

XSLT injection occurs when an attacker influences the stylesheet itself rather than only the data it transforms, so they control the program the XSLT processor executes. The decision point is whether the engine compiles untrusted stylesheet text and whether document() and registered extension functions are available: with them enabled, a stylesheet can read local files, fetch URLs, or in some processors invoke platform code. system-property() fingerprints the engine and version, which tells the attacker which capabilities exist on libxslt, Xalan, or Saxon. The gain ranges from file disclosure and server-side fetch to code execution on extension-rich engines. Proof is a transform whose output reflects a capability call such as system-property() or a document() read of a benign local marker, which a data-only transform could never produce.

- **Precondition chain:** The attacker influences stylesheet text or an included stylesheet, the XSLT engine compiles it with document() or extension functions enabled, and the transform result is observable so the capability output can be read back.
- **Readable differential:** A data-only transform is compared against one whose stylesheet calls a capability function; a finding exists when the engine metadata or a benign file marker appears in the output, and it reverts once only a server-owned stylesheet runs with extensions denied.
- **Empirical grounding:** CWE-611 and CWE-643 anchor this leaf under OWASP Top 10:2025 A05 Injection; SOURCES.md contains no XSLT-specific advisory, so this stays at taxonomy and describes engine capability abuse rather than naming a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as stylesheet control **THEN** start at the parent class [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) (1 hop) for general triage
2. **IF** the attacker controls the stylesheet body **THEN** treat untrusted-stylesheet compilation as the finding and do not compile it in production flows
3. **IF** the stylesheet reaches document() for a file or URL read **THEN** verify the engine resolves document() against a benign local path first
4. **IF** the engine exposes extension functions on Xalan, Saxon, or libxslt **THEN** enumerate which extension namespaces are registered before deeper probing
5. **IF** only the input data is attacker-controlled, not the stylesheet **THEN** route the value to [`xml-attacks-xxe-and-xslt-xpath-and-schema`](../xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md)
6. **IF** system-property() reveals the processor and version **THEN** use it to fingerprint capability before assuming file read or execution
7. **IF** the transform output renders in a browser **THEN** check for XSLT-to-XSS in the generated result tree
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** only a server-owned stylesheet runs and extensions are denied **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Only the input data is attacker-controlled | [`xml-attacks-xxe-and-xslt-xpath-and-schema`](../xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) | Data-level XPath neutralisation differs from control over the stylesheet |
| document() fetches an internal URL | [`ssrf`](../ssrf/SKILL.md) | A server-side fetch from the transform is an SSRF pivot |
| The transform result renders as HTML | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | Output-side scripting is a different sink than the transform engine itself |
| Need parent class methodology | [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate where the stylesheet originates and classify control.** Determine whether the stylesheet is server-owned, user-supplied, or assembled from input, since only influence over the stylesheet is XSLT injection.
2. **Read the engine and its capability flags.** Identify the processor and whether document(), extension functions, and external includes are enabled, because these decide whether influence becomes file read or execution.
3. **Record a data-only baseline.** Run the intended transform with ordinary data and capture the normal result tree as the comparison point.
4. **Fingerprint before escalating.** Use a system-property() read to confirm the engine and version from the output, which tells you which capability functions are even available.
5. **Probe one capability non-destructively.** Attempt a document() read of a benign local marker or a benign extension call, and compare the output against the data-only baseline; do not read sensitive files or reach real services.
6. **Stop condition.** Halt when the transform either (a) reflects engine metadata or a benign marker that proves a capability ran and reverts when extensions are denied, (b) produces only the data-only output, or (c) would require reading a sensitive file, reaching a real service, or executing platform code. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is capability output in the transform result, such as system-property() metadata or a benign document() marker, tied to attacker-influenced stylesheet text, plus the enabled engine feature; a transform of attacker data without stylesheet control is not this finding.
8. **Close with the structural fix.** Compile only vetted server-owned stylesheets, pass user content as bound parameters, and disable document(), extension functions, and external includes at the engine. Verify by replaying the capability probe against the restricted engine.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| system-property('xsl:vendor') or 'xsl:version' reflected in the output | Proves the stylesheet reached a capability function and fingerprints the XSLT engine |
| document('file:///tmp/marker') content appearing in the result tree | Proves the transform can read local files on libxslt, Xalan, or Saxon |
| A registered extension namespace such as a Java or EXSLT prefix in the stylesheet | Proves extension functions are available, the path to code execution on extension-rich engines |
| User input appearing inside the stylesheet text rather than the data document | Proves stylesheet influence, the defining XSLT-injection precondition |
| Transform output containing unescaped markup that renders in a browser | Proves XSLT-to-XSS where the result tree is served as HTML |
| xsl:include or xsl:import resolving an external stylesheet | Proves external stylesheet inclusion, another route to attacker-controlled transform logic |
| An error naming the XSLT processor when a capability call is attempted | Proves the engine attempted the capability, useful to confirm reachability on the transform tier |

## Worked Contrast

**Vulnerable pattern:**

```python
from lxml import etree


def report(data_xml, user_template):
    # The user controls the stylesheet body, so they control the program the
    # XSLT engine runs, including document() and extension calls.
    style = etree.XML(user_template)
    transform = etree.XSLT(style)
    return bytes(transform(etree.XML(data_xml)))
```

**Hardened pattern:**

```python
from lxml import etree

FIXED_STYLE = etree.XSLT(
    etree.parse("templates/report.xslt"),
    access_control=etree.XSLTAccessControl.DENY_ALL,
)


def report(data_xml, user_params):
    # Only a vetted server-owned stylesheet runs; user values arrive as bound
    # parameters and cannot introduce capability calls.
    params = {k: etree.XSLT.strparam(v) for k, v in user_params.items()}
    return bytes(FIXED_STYLE(etree.XML(data_xml), **params))
```

**Why this matters:** The defect compiles an attacker-supplied stylesheet, handing them document() and extension functions. The structural control transforms only with a fixed server-owned stylesheet, passes user data as bound parameters, and denies all access, so no attacker-authored XSLT is ever compiled.

## When It Is NOT This Issue

- **Server-owned stylesheet with bound parameters:** if the stylesheet is fixed and user content enters only as parameters, there is no stylesheet control and no injection.
- **Extensions and document() disabled:** an engine configured to deny document() and extension functions cannot be steered to read files even if stylesheet text is influenced.
- **Data-only transform:** attacker control over the input document, but not the stylesheet, is an XPath or data-handling question, not XSLT injection.
- **Output not reflected:** a transform whose result is never returned or rendered gives no channel to confirm a capability call, so a claimed read is unproven.
- **Static analysis match without compilation:** a stylesheet string stored but never compiled by the engine is not a live transform and is not exploitable as-is.
- **Capability call rejected by the engine:** an engine that raises a not-allowed error for document() or an extension is enforcing the control, so the attempt is a non-finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xml-attacks-xxe-and-xslt-xslt-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xml-attacks-xxe-and-xslt-xslt-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xml-attacks-xxe-and-xslt-xslt-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611, CWE-643 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) - Web and Application (leaf)
- [`xml-attacks-xxe-and-xslt-xpath-and-schema`](../xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xml-attacks-xxe-and-xslt-xslt-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, CWE-643`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/gh_advisories (2), CYBER_CPT/pentesterlab (1), CYBER_CPT/go_exploitdb (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
