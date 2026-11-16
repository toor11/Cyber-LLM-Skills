---
name: xml-attacks-xxe-and-xslt
description: "Covers XML parser attacks beyond basic XXE: XSLT injection and extension abuse, XPath injection, schema and DTD attacks, and parser differentials across OOXML, SOAP and SAML. Use when XML processing is broader than a single entity injection."
family: web-and-application
tier: leaf
triggers: ["xslt injection", "xpath injection", "xml attack", "stylesheet injection", "xslt extension"]
cwe: [CWE-611, CWE-643]
owasp: [A05:2021]
attack: []
capec: [CAPEC-221]
related: [xml-attacks-xxe-and-xslt-xslt-injection, xml-attacks-xxe-and-xslt-xpath-and-schema, sql-injection, cross-site-scripting]
---

# Xml Attacks XXE and Xslt - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This class covers XML processing that goes past raw entity injection: the same document can be transformed by a stylesheet, queried by an XPath expression, or validated against a schema, and each stage is its own interpreter with its own trust decision. In XSLT the engine compiles a stylesheet and may expose document() and extension functions that read files or reach the network; in XPath an expression is built from input and a tautology can widen the node set it returns; in schema and DTD handling a crafted grammar can trigger unbounded expansion. The attacker's leverage is choosing which interpreter mis-trusts input and steering it to disclose data, reach internal services, or exhaust the parser. Confirmation is a differential in what the transform, query, or validator produced, not merely whether a literal string was accepted.

- **Precondition chain:** Untrusted input reaches an XSLT stylesheet, an XPath expression, or a schema or DTD declaration, the engine leaves document(), extension functions, or entity expansion enabled, and the transformed or queried output is observable to the caller.
- **Readable differential:** A benign transform or query is compared against one that bends structure, such as a tautology predicate or a system-property call; a finding exists when the output changes meaning, and it reverts once input is bound and the engine's external features are disabled.
- **Empirical grounding:** CWE-611 and CWE-643 anchor this class under OWASP Top 10:2025 A05 Injection; SOURCES.md has no XSLT-specific or XPath-specific advisory, so those stay at taxonomy, while the parser-differential members are grounded in CVE-2025-25291 and CVE-2025-25292 where two parsers disagreed over the same XML document.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is a stylesheet reaching extension functions or document() **THEN** switch to [`xml-attacks-xxe-and-xslt-xslt-injection`](../xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) (1 hop)
2. **IF** the target builds an XPath query or expands a schema or DTD **THEN** switch to [`xml-attacks-xxe-and-xslt-xpath-and-schema`](../xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) (1 hop)
3. **IF** the document is parsed with external entities rather than transformed **THEN** switch to [`xxe`](../xxe/SKILL.md) (1 hop) for the entity-resolution class
4. **IF** input is concatenated into an XPath predicate against an XML store **THEN** treat it as query injection and confirm with a true-versus-false predicate pair
5. **IF** a stylesheet reaches document() or a registered extension namespace **THEN** classify as XSLT capability abuse and check the engine's access controls
6. **IF** a schema or DTD triggers unbounded entity expansion **THEN** measure parse time and memory against a benign baseline before concluding
7. **IF** two XML components disagree about the same bytes **THEN** route to parser-differential analysis in [`xxe-parser-differential-bypass`](../xxe-parser-differential-bypass/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** the parser rejects DTDs and input never reaches an XPath or XSLT sink **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Input is an XPath query to a directory service | [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) | Routes to the query-injection sibling rather than XML document transformation |
| The core issue is external-entity resolution | [`xxe`](../xxe/SKILL.md) | Entity resolution is a different invariant than XSLT or XPath neutralisation |
| The transform fetches an internal URL | [`ssrf`](../ssrf/SKILL.md) | A server-side fetch from document() is an SSRF pivot |
| Target matches `xml-attacks-xxe-and-xslt-xslt-injection` | [`xml-attacks-xxe-and-xslt-xslt-injection`](../xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `xml-attacks-xxe-and-xslt-xpath-and-schema` | [`xml-attacks-xxe-and-xslt-xpath-and-schema`](../xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate which XML interpreter receives the input and classify it.** Decide whether the sink is an XSLT transform, an XPath expression, or a schema and DTD validator, because the vulnerable feature and the fix differ for each.
2. **Read the engine configuration.** Determine whether document(), extension functions, external stylesheet includes, and entity expansion are enabled, since these flags, not the payload, decide reachability.
3. **Record a benign baseline.** Run the transform or query with ordinary input and capture the exact output structure that correct processing produces.
4. **Choose the branch from observed behaviour.** If a tautology predicate changes the returned node set, it is XPath injection; if system-property() or document() output appears, it is XSLT capability abuse; if a bounded nested entity inflates parse time, it is expansion.
5. **Probe one layer with a non-destructive differential.** Send a single structure-bending input (a true-versus-false predicate, a system-property read, or a small bounded expansion) and compare the output against the baseline.
6. **Stop condition.** Halt when the probe either (a) changes the output's meaning in a way that reverts when input is bound, (b) produces no change across baselines, or (c) would require reading real files, reaching real internal services, or exhausting the server to advance. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable differential in the transform or query output tied to attacker input, plus the engine flag that permitted it; an error message or a reflected string alone is not proof unless it changes with the structure of the input.
8. **Close with the structural fix.** Bind XPath values as variables, compile only server-owned stylesheets with document() and extensions denied, and disable DTD and external resolution with a bounded entity limit. Verify by replaying the probe against the hardened configuration.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An XPath predicate whose returned node set flips for a tautology input | Proves XPath injection on an XML store where input alters query structure rather than data |
| system-property('xsl:vendor') output reflected in a transform result | Proves an attacker-influenced stylesheet reached a capability function on the XSLT engine |
| document('file:///...') resolving inside a transform | Proves the stylesheet can read files or URLs, the high-impact XSLT capability on libxslt, Xalan, or Saxon |
| A bounded nested-entity document inflating parse time versus baseline | Proves unbounded entity expansion is enabled in the DTD or schema handler, an availability risk |
| An XInclude element pulling an unexpected resource into the tree | Proves the parser honours xi:include, a distinct inclusion path from DOCTYPE entities |
| Two parser stages disagreeing on whether a DOCTYPE is present | Proves a parser differential, routed to the dedicated bypass child for confirmation |
| A schema import fetched from an attacker-reachable URL | Proves schema resolution reaches the network, widening the transform and validation surface |

## Worked Contrast

**Vulnerable pattern:**

```python
from lxml import etree


def render(xml_bytes, xslt_bytes):
    # The stylesheet is compiled with document() and extensions fully enabled,
    # so the transform can read files and reach the network.
    transform = etree.XSLT(etree.fromstring(xslt_bytes))
    return bytes(transform(etree.fromstring(xml_bytes)))
```

**Hardened pattern:**

```python
from lxml import etree


def render(xml_bytes, xslt_bytes):
    # Parse with no entity resolution or network, then deny file, write, and
    # network reach from inside the transform.
    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    style = etree.fromstring(xslt_bytes, parser)
    control = etree.XSLTAccessControl.DENY_ALL
    transform = etree.XSLT(style, access_control=control)
    return bytes(transform(etree.fromstring(xml_bytes, parser)))
```

**Why this matters:** The defect compiles a stylesheet with document() and extension functions live, so the transform becomes a file and network primitive. The structural control parses without entity resolution or network access and applies XSLTAccessControl.DENY_ALL, so the engine's capability functions cannot reach outside the document.

## When It Is NOT This Issue

- **Static server-owned stylesheet:** a transform that only ever compiles a fixed, vetted stylesheet with user data as bound parameters is not attacker-controlled and is not this class.
- **XPath over a constant document:** an expression built only from server constants, with no input reaching the query text, cannot be injected.
- **Error reflects input without structure change:** an XML parse error echoing the input is a verbosity issue, not injection, unless the returned node set or output actually changes with structure.
- **Entity expansion already capped:** a parser that enforces an expansion limit and rejects nested-entity documents is enforcing the control, so a billion-laughs attempt is a non-finding.
- **Extensions disabled at the engine:** a transform whose engine has document() and extension functions turned off cannot be steered to read files even if the stylesheet is influenced.
- **Schema fetched from a pinned internal mirror:** a validator that resolves imports only from a fixed trusted path is not reaching attacker-controlled network resources.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xml-attacks-xxe-and-xslt` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xml-attacks-xxe-and-xslt` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xml-attacks-xxe-and-xslt
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611, CWE-643 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xml-attacks-xxe-and-xslt-xslt-injection`](../xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) - Web and Application (leaf)
- [`xml-attacks-xxe-and-xslt-xpath-and-schema`](../xml-attacks-xxe-and-xslt-xpath-and-schema/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xml-attacks-xxe-and-xslt` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, CWE-643`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (9), SecEval/owasp_wstg (2), CYBER_CPT/hacktricks (2), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
