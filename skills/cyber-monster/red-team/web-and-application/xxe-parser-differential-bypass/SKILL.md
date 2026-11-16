---
name: xxe-parser-differential-bypass
description: XXE parser differential and filter bypass. Covers bypassing entity blocking through alternate encodings, XInclude, parameter entities, and differences between libxml, Xerces and .NET parsers. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["xinclude", "xxe bypass", "entity blocking bypass", "parser differential xxe"]
cwe: [CWE-611]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-221]
related: [xxe, xxe-file-disclosure, xxe-oob-exfiltration, xxe-ooxml-and-svg]
parent: xxe
---

# XXE Parser Differential Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A parser differential bypass defeats an XXE filter by making the component that inspects the document and the component that consumes it disagree about what the bytes mean, so the bytes that were checked are not the bytes that were parsed. A common shape is a pre-check that scans raw bytes for a literal <!DOCTYPE while the real parser decodes UTF-16 or honours a BOM, so the hidden DOCTYPE slips through; another is reaching a file through xi:include where DTD entities are blocked, or moving declarations into an external parameter entity when internal general entities are rejected. The decision point is that two stages apply different grammars or charsets to one input. The grounding case is the ruby-saml parser disagreement where the verified bytes differed from the consumed bytes. Proof is a document that the filter accepts yet the parser still processes as a DTD, shown by a benign entity that dereferences past the control.

- **Precondition chain:** A filter or pre-check decides on the document separately from the parser that consumes it, the two apply different charsets or grammars, and the parser still resolves entities or inclusions once the input slips the check.
- **Readable differential:** A document that the filter blocks in one encoding is compared against the same document in UTF-16 or via XInclude; a finding exists when the re-encoded form passes the filter yet still dereferences, and it stops once one hardened parser decides after canonical decoding.
- **Empirical grounding:** CWE-611 anchors this leaf under OWASP Top 10:2025 A05 Injection, grounded in SOURCES.md by CVE-2025-25291 and CVE-2025-25292, the ruby-saml parser-differential advisories where two parsers consumed the same document differently so the bytes verified were not the bytes parsed.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as a filter bypass **THEN** start at the parent class [`xxe`](../xxe/SKILL.md) (1 hop) for general triage
2. **IF** a pre-check scans raw bytes while a different parser consumes them **THEN** test whether a UTF-16 or BOM-prefixed document slips the byte-level screen
3. **IF** DOCTYPE is blocked but XInclude is not **THEN** use xi:include to reach a benign file without declaring a DTD
4. **IF** internal general entities are blocked but parameter entities are not **THEN** move the declarations into an external DTD
5. **IF** the stack mixes libxml, Xerces, and .NET parsers **THEN** identify which parser actually resolves the entity before concluding
6. **IF** an encoding declaration disagrees with the transport charset **THEN** exploit the decode gap between the validator and the parser
7. **IF** a bypass yields in-band read **THEN** route to [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** one hardened parser decides after canonical decoding and rejects DTDs **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The bypass yields in-band file read | [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) | The read channel is a different invariant than the differential that enabled it |
| The bypass is blind | [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) | The callback channel differs from the parser disagreement itself |
| The same disagreement appears in WAF normalisation | [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) | Container-level parsing differentials generalise beyond XML parsers |
| Need parent class methodology | [`xxe`](../xxe/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the check and the consuming parser separately.** Identify what rejects a DOCTYPE, whether a regex over raw bytes, a string scan, or a validating parse, and identify the parser that actually consumes the document afterwards.
2. **Characterise the grammar and charset of each.** Determine the encoding the check assumes versus the encoding the parser honours, and whether the parser supports XInclude or external parameter entities the check does not model.
3. **Record the blocked baseline.** Confirm that the straightforward DOCTYPE in the expected charset is in fact rejected, so any later pass is attributable to the differential and not to a disabled filter.
4. **Re-encode or re-route the same payload.** Submit the document as UTF-16 or with a BOM, or express the read through xi:include or an external parameter entity, so the check and the parser see different things.
5. **Confirm the parser still dereferences.** Use a benign entity or inclusion and verify it resolves past the control, choosing an in-band marker or a callback depending on the response channel.
6. **Stop condition.** Halt when the input either (a) passes the check yet still dereferences and reverts when a single hardened parser is used, (b) is rejected by both stages, or (c) would require reading real secrets to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a document the filter accepts that the parser still processes as a DTD or inclusion, shown by a benign marker dereferencing, plus the specific disagreement (charset, grammar, or entity type); a payload the filter already blocks is not proof.
8. **Close with the structural fix.** Remove the separate byte-level screen and let one hardened parser decide after canonical decoding, with DTDs, external entities, and XInclude all disabled. Verify by replaying every re-encoded form and seeing each rejected by the single parser.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A UTF-16 document that passes a raw-byte DOCTYPE scan yet is parsed as a DTD | Proves a charset differential between the screen and the parser, the central bypass for this leaf |
| An xi:include reaching a file where DOCTYPE entities are blocked | Proves a grammar differential, since XInclude is a non-entity inclusion the filter did not model |
| An external parameter entity resolving where internal entities are rejected | Proves an entity-type differential between the filter and the parser |
| A BOM-prefixed body that the validator and parser decode differently | Proves a decode gap that the single-parser fix closes on libxml or .NET stacks |
| The straightforward DOCTYPE blocked while a re-encoded form passes | Proves the control exists and is being bypassed rather than simply absent |
| Two parsers in the stack disagreeing on whether a DOCTYPE is present | Proves the verified bytes differ from the consumed bytes, as in the ruby-saml advisories |

## Worked Contrast

**Vulnerable pattern:**

```python
from lxml import etree


def load(xml_bytes):
    # A byte-level screen scans for a literal <!DOCTYPE, but a UTF-16 document
    # does not contain those bytes, so the real parser still sees the DOCTYPE.
    if b"<!DOCTYPE" in xml_bytes:
        raise ValueError("DTD not allowed")
    return etree.fromstring(xml_bytes)
```

**Hardened pattern:**

```python
from lxml import etree


def load(xml_bytes):
    # One hardened parser is the only authority: it decodes, then refuses DTDs,
    # external entities, network, and XInclude, with no separate byte screen.
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                             no_network=True)
    root = etree.fromstring(xml_bytes, parser)
    if root.getroottree().docinfo.doctype:
        raise ValueError("DTD not allowed")
    return root
```

**Why this matters:** The defect splits the decision: a raw-byte screen misses a UTF-16 DOCTYPE that the decoding parser then honours. The structural control removes the separate screen so one hardened parser decodes and decides, rejecting DTDs and external resolution after it has seen the real bytes.

## When It Is NOT This Issue

- **Payload the filter already blocks:** a DOCTYPE in the expected charset that the check rejects is the control working; only a re-encoded form that slips through is a bypass.
- **Single hardened parser:** a stack where one entity-disabled parser both validates and consumes has no differential to exploit.
- **Re-encoded form also rejected:** if the UTF-16 or XInclude variant is refused too, there is no disagreement and no finding.
- **Charset the parser cannot decode:** a body in an encoding the parser rejects outright is dropped, not bypassed, so no dereference occurs.
- **XInclude disabled:** a parser with XInclude turned off will not resolve xi:include even when DOCTYPE entities are blocked, so that route is closed.
- **No dereference after the pass:** input that passes the screen but whose entity never resolves proves the parser is hardened, which is a non-finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xxe-parser-differential-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xxe-parser-differential-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xxe-parser-differential-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xxe`](../xxe/SKILL.md) - Web and Application (core)
- [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) - Web and Application (leaf)
- [`xxe-oob-exfiltration`](../xxe-oob-exfiltration/SKILL.md) - Web and Application (leaf)
- [`xxe-ooxml-and-svg`](../xxe-ooxml-and-svg/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xxe-parser-differential-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/github_security_md (1), CYBER_CPT/vulhub (1), CYBER_CPT/nuclei_templates (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
