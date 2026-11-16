---
name: xxe-file-disclosure
description: XXE local file disclosure. Covers classic in-band file read via external entities across XML parsers, including encoding constraints and multi-line file limitations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["xxe file read", "xxe local file", "xxe disclosure"]
cwe: [CWE-611]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-221]
related: [xxe, xxe-oob-exfiltration, xxe-ooxml-and-svg, xxe-parser-differential-bypass]
parent: xxe
---

# XXE File Disclosure - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

In-band XXE file disclosure uses an external entity whose value is a local file and relies on the application reflecting that value back in its response. The decision point is the parser: with entity resolution on, a SYSTEM entity pointing at file:// is dereferenced and the file bytes are substituted where the entity is referenced, then echoed wherever the document is rendered. The constraint that defines this leaf is encoding: a file with newlines, XML metacharacters, or non-UTF-8 bytes can break the document, so on PHP stacks a php://filter base64 wrapper is used to carry the bytes intact, and multi-line files may need a wrapper or a move to out-of-band. The gain is reading configuration, credentials, or source within the service account's reach. Proof is a benign local marker returning in the response that the plain document did not contain.

- **Precondition chain:** The parser resolves external entities, the application reflects parsed content back to the caller, and the target file is readable by the service account and survives being embedded in the XML document or a wrapper.
- **Readable differential:** A plain document is compared against one declaring a file:// SYSTEM entity referenced in the output; a finding exists when the file marker appears in the response, and it disappears once entity resolution is disabled.
- **Empirical grounding:** CWE-611 anchors this leaf under OWASP Top 10:2025 A05 Injection; SOURCES.md has no file-disclosure-specific product advisory, so this stays at taxonomy, with the structural fix being to disable external entity and DTD resolution in the parser.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as in-band file read **THEN** start at the parent class [`xxe`](../xxe/SKILL.md) (1 hop) for general triage
2. **IF** the response reflects the parsed document **THEN** use a benign internal entity first, then a SYSTEM entity to a short benign local file
3. **IF** the target file has multiple lines and the read truncates **THEN** wrap the read in a php://filter base64 layer to preserve the bytes
4. **IF** the stack is PHP with wrappers available **THEN** prefer php://filter over raw file:// for encoding safety
5. **IF** the target file contains XML-breaking characters **THEN** move the read into CDATA via an external DTD or switch to an out-of-band channel
6. **IF** nothing is reflected in-band **THEN** route to [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md)
7. **IF** the entry point is an uploaded office or SVG document **THEN** route to [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** entity resolution is off and no file bytes return **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| No in-band reflection is available | [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) | A blind callback channel is a different mechanism than in-band read |
| The entity reaches an internal URL | [`ssrf`](../ssrf/SKILL.md) | File read and server-side fetch are distinct impacts of the same entity |
| A filter blocks the DOCTYPE | [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) | Getting past the filter is a separate invariant from reading the file |
| Need parent class methodology | [`xxe`](../xxe/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the parse and the reflection path.** Confirm both that the endpoint parses XML with entities on and that parsed content is echoed back, because in-band disclosure needs the reflection, not just the parse.
2. **Record a benign baseline.** Submit a well-formed document and capture exactly where its element values appear in the response, since that location is where a dereferenced entity will surface.
3. **Confirm entity resolution with an internal entity.** Declare a benign internal entity and verify it expands in the reflected output before attempting any file read.
4. **Read a short benign local marker.** Point a SYSTEM entity at a short, single-line benign file or a placed marker and confirm it returns where the baseline value appeared.
5. **Handle the encoding constraint.** If the file is multi-line or contains XML metacharacters and the read truncates or errors, switch to a php://filter base64 wrapper on PHP, or wrap in CDATA, rather than concluding no vulnerability.
6. **Stop condition.** Halt when the response either (a) returns the benign file marker and stops returning it once resolution is disabled, (b) never reflects the entity despite confirmed parsing, or (c) would require reading real credential files to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a benign local file marker appearing in the response at the baseline reflection point, tied to the declared entity and absent from the plain document, plus the parser setting that allowed it; a parse error alone is not proof.
8. **Close with the structural fix.** Disable DTD loading and external entity resolution on the parser so a file:// entity expands to nothing. Verify by replaying the marker read and seeing the DOCTYPE rejected.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A file:// SYSTEM entity returning a benign marker at the reflection point | Proves in-band file read on the parsing tier, the defining condition for this leaf |
| A php://filter base64 wrapper returning encoded bytes of a benign file | Proves the encoding workaround is needed and works on a PHP stack |
| A single-line read succeeding while a multi-line read truncates | Proves the newline and metacharacter constraint that distinguishes in-band disclosure |
| A benign internal entity expanding in the reflected output | Proves entity resolution is on before any external file is attempted |
| An entity read returning nothing while the DOCTYPE is accepted | Proves resolution is disabled, the inert non-finding state for this leaf |
| The reflection point echoing the entity inside an element the baseline mapped | Proves the channel is genuinely in-band rather than an incidental error echo |

## Worked Contrast

**Vulnerable pattern:**

```python
from lxml import etree


def load(xml_bytes):
    # Entities are resolved and the DTD is loaded, so a SYSTEM entity pulls a
    # local file into the tree that the caller then reads back.
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    return etree.fromstring(xml_bytes, parser)
```

**Hardened pattern:**

```python
from lxml import etree


def load(xml_bytes):
    # No DTD, no entity resolution, no network: a declared SYSTEM entity
    # expands to nothing, so no file content can return in-band.
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                             no_network=True, dtd_validation=False)
    root = etree.fromstring(xml_bytes, parser)
    return root
```

**Why this matters:** The defect resolves entities and loads the DTD, so a file:// SYSTEM entity substitutes file bytes into the reflected document. The structural control disables DTD loading and entity resolution, so the entity never dereferences and no file content can appear in the response.

## When It Is NOT This Issue

- **Parse without reflection:** an endpoint that parses XML but never echoes parsed content back gives no in-band channel, so this leaf does not apply even if entities resolve.
- **Resolution disabled:** a parser with external entities off expands the file entity to nothing, so an empty reflection is a non-finding.
- **Binary or large file assumed readable:** a multi-line or binary target that breaks the document is not evidence of failure; it is the encoding constraint, and absence of a wrapper attempt is incomplete testing.
- **Echoed DOCTYPE string:** a response that reflects the literal DOCTYPE text without any file bytes is echoing input, not disclosing a file.
- **Marker from the request, not the file:** a marker that appears because it was in the submitted element, not because the entity dereferenced, is not proof of file read.
- **Non-UTF-8 file silently dropped:** a file the parser cannot encode may be dropped by the parser itself, which is a limitation of the read, not a separate vulnerability.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xxe-file-disclosure` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xxe-file-disclosure` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xxe-file-disclosure
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xxe`](../xxe/SKILL.md) - Web and Application (core)
- [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) - Web and Application (leaf)
- [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) - Web and Application (leaf)
- [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xxe-file-disclosure` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 2 |
| Top sources | OffsecCyber (3), bug-bounty-pentest-en (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
