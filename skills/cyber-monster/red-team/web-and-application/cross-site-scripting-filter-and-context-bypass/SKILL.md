---
name: cross-site-scripting-filter-and-context-bypass
description: XSS filter and context bypass. Covers bypassing tag and attribute blocklists, event-handler restrictions, length limits, and encoding-based filters across HTML, attribute, script, style and URL contexts. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["xss filter bypass", "waf xss", "xss payload bypass", "context escape"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-reflected, cross-site-scripting-stored, cross-site-scripting-dom]
parent: cross-site-scripting
---

# Cross Site Scripting Filter and Context Bypass - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

An injection point is already known, but a blocklist filter or a WAF stands between input and the sink, so the task is defeating that filter rather than finding the bug. Blocklists fail because they enumerate bad strings: a mixed-case tag, an uncommon element such as details with ontoggle, an unexpected event handler, an entity- or percent-encoded break, or a parser-differential between how the filter and the browser read the same bytes all slip through. WAFFLED shows container-level parsing discrepancies producing over a thousand bypasses, and Unicode normalization, full-width forms, compatibility folding, and best-fit mapping add more. The security decision is that filtering is a blocklist rather than context-aware output encoding, so a variant the list never anticipated reaches the sink intact. The attacker gains the same script execution; the proof is a filtered-versus-unfiltered differential plus browser execution.

- **Precondition chain:** An injection sink exists behind a blocklist filter or WAF, the filter and the browser disagree on how to parse some encoding or element, a variant exists that the blocklist does not cover, and that variant reaches the sink and executes.
- **Readable differential:** A canonical payload that the filter blocks versus an equivalence-class variant that is not enumerated; a finding exists when the variant passes the filter and still executes at the sink, and it closes once filtering is replaced by context-aware output encoding.
- **Empirical grounding:** CWE-79 under OWASP Top 10:2025 A05:2025 Injection; WAFFLED (arXiv 2503.10846) documents container-level parsing discrepancies yielding over a thousand WAF bypasses, and the Unicode normalization bypass class (full-width, compatibility folding, best-fit mapping) from 2025 research anchors the encoding-layer evasions.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a filter or blocklist standing before the sink **THEN** start at the parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) first
2. **IF** the filter sits in a CDN or WAF rather than the application **THEN** treat it as a parser-differential problem and read [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md)
3. **IF** the bypass relies on Unicode normalization or best-fit mapping **THEN** treat the charset divergence and read [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md)
4. **IF** a Content-Security-Policy also blocks the resulting inline script **THEN** switch to policy-level gadgets and read [`cross-site-scripting-csp-bypass`](../cross-site-scripting-csp-bypass/SKILL.md)
5. **IF** the sink is a client-side DOM assignment rather than a server reflection **THEN** reclassify as a DOM flow and read [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md)
6. **IF** a sanitizer rewrites the payload and the break is a parser mutation **THEN** test the sanitizer output as an mXSS mutation rather than a raw bypass
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** every equivalence-class variant is blocked and the sink encodes output anyway **THEN** STOP and record a verified non-finding rather than reporting a blocked probe

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Filter lives in a CDN or WAF | [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) | Invariant is parser-differential evasion at the gateway |
| Bypass uses Unicode normalization or best-fit mapping | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | Invariant is charset normalization divergence between filter and sink |
| Inline script is also blocked by a CSP | [`cross-site-scripting-csp-bypass`](../cross-site-scripting-csp-bypass/SKILL.md) | Routes to policy-level execution gadgets |
| Need parent class methodology | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Pin the sink context and the filter position.** Identify whether the value lands in HTML, an attribute, a script, a style, or a URL, and whether the filter is an application blocklist or a gateway WAF, because the bypass must satisfy both the context and the filter.
2. **Characterise what the filter blocks.** Send canonical probes and record which exact strings are rejected, so the blocklist's enumerated set is known before crafting variants.
3. **Derive equivalence-class variants for the context.** From the known-blocked set, build variants that are semantically equal at the sink but lexically different: case changes, alternate tags and handlers, entity or percent encoding, and Unicode normalization forms.
4. **Record a blocked-canonical baseline.** Confirm the canonical payload is rejected and note the exact rejection, giving the control against which a passing variant is measured.
5. **Apply the filtered-versus-unfiltered differential.** Send each variant and compare reachability to the sink; a variant that passes the filter and arrives intact is selected from evidence, then confirmed by browser execution rather than reflection.
6. **Stop condition.** Halt when the probe either (a) finds a variant that passes the filter and executes at the sink, reverting once output is context-encoded, (b) sees every variant blocked with the sink also encoding, or (c) would require a weaponised payload to advance beyond a benign marker. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a specific equivalence-class variant that the filter allows and that executes at the sink in a browser, tied to the canonical form it was derived from, plus the sink's missing output encoding. A variant that passes the filter but is encoded at the sink is not proof.
8. **Close with the structural fix and verify.** Replace blocklist filtering with context-aware output encoding at the sink and normalise input to a single canonical form before any check, then replay the whole variant set and confirm all render inert.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A mixed-case tag like <ScRiPt> passing a lowercase-only blocklist | Proves a case-sensitivity gap in the filter that the browser ignores when parsing |
| An uncommon element such as <details open ontoggle=> reaching the sink | Proves the blocklist enumerates common tags but misses the event-handler surface |
| Entity- or percent-encoded break decoded only after the filter check | Proves an order-of-operations gap where decoding happens past the enumerated blocklist |
| A full-width or compatibility-normalized character folding to a blocked one | Proves a Unicode normalization divergence between the filter and the rendering sink |
| A multipart or content-type trick the WAF parses differently from the app | Proves a container-level parser differential of the WAFFLED class at the gateway |
| A canonical payload blocked while an equivalence-class variant executes | Proves filtering rather than context encoding is the only control, the defining evidence |

## Worked Contrast

**Vulnerable pattern:**

```python
import re

def strip_xss(value):
    # blocklist removes one spelling of <script>; mixed case and svg survive
    return re.sub(r"<script>", "", value, flags=re.IGNORECASE)
```

**Hardened pattern:**

```python
import html
import unicodedata

def to_html_text(value):
    # canonicalize first, then context-encode so no tag or handler survives as markup
    canonical = unicodedata.normalize("NFKC", value)
    return html.escape(canonical, quote=True)
```

**Why this matters:** The vulnerable function tries to delete one spelling of a script tag, so any unlisted tag, handler, or encoding reaches the sink. The fix stops filtering by pattern: it normalises to a single canonical form and then applies context-aware HTML encoding, so every angle bracket and quote becomes inert regardless of the variant used.

## When It Is NOT This Issue

- **Output encoding at the sink:** a value context-encoded where it renders is safe even if a WAF variant reaches it, because it is displayed as text.
- **Variant blocked and sink encodes:** when both the filter rejects variants and the sink encodes, there is no reachable execution.
- **WAF block mistaken for app safety:** a gateway rejection proves the WAF fired, not that the underlying sink is safe or unsafe.
- **Normalization applied before checks:** input canonicalized to one form before validation removes the encoding-layer gap.
- **Reflected but non-HTML content type:** a variant echoed in a JSON or text/plain response with a correct type is not parsed as markup.
- **Self-only execution:** a bypass that runs only in the attacker's own session with no cross-user reach is not reportable.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-filter-and-context-bypass` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-filter-and-context-bypass` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-filter-and-context-bypass
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-79 | Mapping: T1059]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-filter-and-context-bypass` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/gh_advisories (5), CYBER_CPT/osv (4), hackerone_disclosed_reports (3), CYBER_CPT/payloads_all_the_things (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
