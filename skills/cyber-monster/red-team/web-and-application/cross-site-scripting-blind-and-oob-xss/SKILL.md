---
name: cross-site-scripting-blind-and-oob-xss
description: Blind and out-of-band cross-site scripting. Covers XSS in admin-only views, log viewers, PDF generators and headless-browser render paths, detected through callbacks and stored-trigger confirmation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["blind xss", "oob xss", "xss in admin panel", "headless xss"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-reflected, cross-site-scripting-stored, cross-site-scripting-dom]
parent: cross-site-scripting
---

# Cross Site Scripting Blind and Oob XSS - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A payload is stored through one interface but rendered in a privileged context the attacker never sees directly, an operator audit console, a log viewer, a support ticket panel, or a server-side PDF or headless-browser render path. Because the render happens out of band, the only signal is an out-of-band callback or a stored-trigger confirmation when the privileged viewer opens the record. The security decision is still output encoding at the privileged render sink, but the verification model inverts: there is no immediate reflection to read, so the probe is an inert marker carrying a unique callback identifier. The attacker gains script execution in a high-value session such as an administrator's, so impact is often greater than reflected XSS. Confirmation is a callback fired from the privileged render, correlated to the exact injected record.

- **Precondition chain:** Input is stored or forwarded, it is later rendered in a privileged or server-side viewer without context encoding, the attacker cannot see that render directly, and a callback or stored-trigger channel can correlate execution to the injected record.
- **Readable differential:** A stored record with a benign callback marker versus one without; a finding exists when opening the privileged view emits the correlated out-of-band callback, and it stops once the privileged sink encodes the stored value.
- **Empirical grounding:** CWE-79 under OWASP Top 10:2025 A05:2025 Injection describes this class; SOURCES has no blind-XSS-specific advisory, so grounding stays at the CWE and the out-of-band verification model rather than a named CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a deferred privileged-viewer render **THEN** start at the parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) first
2. **IF** execution is immediate and reflected in the same response **THEN** reclassify as reflected and read [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md)
3. **IF** confirmation depends on a DNS or HTTP callback oracle **THEN** treat the oracle itself and read [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md)
4. **IF** the payload fires inside a server-side PDF or headless renderer **THEN** treat the renderer reach and read [`pdf-and-headless-renderer-injection`](../pdf-and-headless-renderer-injection/SKILL.md)
5. **IF** the stored value is served back to ordinary users rather than operators **THEN** reclassify as stored and read [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md)
6. **IF** a sanitizer runs before the privileged render and the break is a mutation **THEN** test the sanitizer output path as a parser mutation, not a raw injection
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no callback fires after a reasonable review window and no trigger confirms **THEN** STOP and record a verified non-finding rather than assuming a silent render

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Execution is same-response and reflected | [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) | Routes to immediate reflection rather than a deferred callback |
| Confirmation needs a DNS or HTTP callback oracle | [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) | Invariant is out-of-band signal correlation |
| Payload executes in a headless PDF renderer | [`pdf-and-headless-renderer-injection`](../pdf-and-headless-renderer-injection/SKILL.md) | Invariant is a server-side renderer sink with SSRF reach |
| Need parent class methodology | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate the privileged render paths that consume stored input.** List operator consoles, log viewers, ticket panels, and PDF or screenshot generators that display fields attackers can set.
2. **Map which stored field feeds which privileged sink.** Correlate the input interface to the viewer that renders it, since the finding lives at the viewer's encoding, not the input form.
3. **Set up a correlated out-of-band oracle.** Mint a unique callback identifier per candidate field so a later hit names exactly which record and which viewer executed, because there is no inline response to read.
4. **Store an inert baseline first.** Submit the field with a plain correlated marker and confirm it is accepted, establishing that the record exists before any active payload.
5. **Submit the callback-marker differential.** Store the same field carrying an inert element that would request the unique callback only if rendered as active content, then wait for the privileged viewer to open it.
6. **Stop condition.** Halt when the probe either (a) emits the correlated callback from the privileged render and stops once that sink encodes the value, (b) produces no callback across a full review window with the record confirmed stored, or (c) would require interacting with a real operator's live session beyond the callback. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is an out-of-band callback whose unique identifier maps to the exact injected record and privileged viewer, plus the stored field and the un-encoding sink. A callback with no record correlation, or a mere stored string, is not proof.
8. **Close with the structural fix and verify.** Apply context-aware encoding at the privileged render sink and sandbox any server-side renderer, then re-store the callback marker and confirm no callback fires when the viewer opens the record.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A stored field rendered unencoded in an operator-only audit console | Proves a blind sink in a privileged viewer where execution occurs in an admin session |
| An inert element carrying a per-record unique callback identifier | Proves correlation capability, mapping any later execution to the exact injected record |
| A server-side PDF or headless-browser render of attacker-set fields | Proves a render-path sink that may also expose SSRF from the renderer's network position |
| A delayed callback arriving long after submission when a viewer opens the record | Proves deferred execution in a human-review workflow on the privileged stack |
| A User-Agent, referer, or filename field surfaced verbatim in a log viewer | Proves a log-render sink where metadata fields reach a privileged HTML context |
| No same-response reflection despite confirmed storage | Proves the blind model, directing verification to callbacks rather than inline markers |

## Worked Contrast

**Vulnerable pattern:**

```python
def render_audit_row(entry):
    # operator-only audit console writes the stored user agent straight into HTML
    return "<td>" + entry["user_agent"] + "</td>"
```

**Hardened pattern:**

```python
from markupsafe import escape

def render_audit_row(entry):
    # encode at the point of output so a stored payload cannot execute in the admin view
    return "<td>{}</td>".format(escape(entry["user_agent"]))
```

**Why this matters:** The vulnerable renderer concatenates a stored, attacker-settable user agent into the operator console HTML, so a payload fires in the admin session when the row is viewed. The fix encodes the value for the HTML context at render time, so the stored string is displayed as inert text no matter who views it.

## When It Is NOT This Issue

- **Callback with no record correlation:** an out-of-band hit that cannot be tied to a specific injected record may come from an unrelated scanner and is not proof.
- **Stored string never rendered as HTML:** a value shown only in a plain-text or JSON operator API is not parsed as markup.
- **Privileged sink already encodes:** an admin console that escapes fields renders the payload inert even though it is stored.
- **Self-only operator view:** a field visible only in the attacker's own tenant console with no higher-privilege viewer has no cross-principal impact.
- **Renderer blocks external fetches:** a PDF or headless renderer with network egress disabled cannot emit the callback even if it parses markup.
- **Test-data artefact:** a callback triggered by the assessor opening the record in their own browser, not by the privileged viewer, is a measurement error.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-blind-and-oob-xss` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-blind-and-oob-xss` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-blind-and-oob-xss
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-blind-and-oob-xss` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 5 |
| Top sources | OffsecCyber (8), CYBER_CPT/osv (3), CYBER_CPT/nuclei_templates (2), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
