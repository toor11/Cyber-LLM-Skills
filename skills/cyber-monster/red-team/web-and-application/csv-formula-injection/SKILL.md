---
name: csv-formula-injection
description: Injects spreadsheet formulas into exported CSV and XLSX files to achieve command execution or data exfiltration when an analyst opens the file. Use when an application exports user-controlled values into a spreadsheet.
family: web-and-application
tier: leaf
triggers: ["csv injection", "formula injection", "spreadsheet injection", "excel injection", "dyngnosis"]
cwe: [CWE-1236]
owasp: [A03:2021]
attack: []
capec: [CAPEC-62]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Csv Formula Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

When an application exports user-supplied values into CSV or XLSX and a spreadsheet program later opens the file, a cell whose text begins with a formula trigger (`=`, `+`, `-`, `@`, and a leading tab or carriage return in some parsers) is evaluated as a formula rather than shown as text. The security decision is made by the exporter: whether it neutralises leading formula characters before writing the cell. The data never executes in the web application; the danger materialises in the analyst's spreadsheet client, which may run HYPERLINK, WEBSERVICE, DDE, or external-reference formulas. The attacker gains formula evaluation (data egress via WEBSERVICE or HYPERLINK, or command execution via legacy DDE) in the context of whoever opens the export. Confirmation is purely structural: the exported cell begins with a trigger character while the benign control cell does not.

- **Precondition chain:** user-controlled text is written into an exported spreadsheet cell, the exporter does not neutralise a leading formula trigger, and a spreadsheet application opens the file and evaluates formulas.
- **Readable differential:** a benign control cell beginning with a letter or space versus a probe cell whose first character is a formula trigger; a finding exists when the exported bytes preserve the leading trigger on the probe cell, and it closes when the exporter prefixes or quotes the value so the cell is text.
- **Empirical grounding:** CWE-1236 Improper Neutralization of Formula Elements in a CSV File, mapped to OWASP Top 10:2025 A05 Injection and the OWASP WSTG CSV-injection test. The 2025 anchor is the USENIX WOOT'25 study 'Comma Separated Vulnerabilities', which built CSVScan and found 8 spreadsheet applications and 4 libraries offering no formula-injection protection.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the app exports user-controlled fields to CSV or XLSX that staff download **THEN** this is the primary case; build the leading-trigger differential on the export
2. **IF** the field is rendered as HTML rather than exported **THEN** route to [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md); the sink is a browser, not a spreadsheet
3. **IF** the export is XLSX and cells carry explicit types **THEN** check whether string cells still begin with a trigger, since type-tagging can mask it
4. **IF** the trigger is a leading tab, carriage return, or space-then-equals **THEN** test whitespace-prefixed triggers that some parsers still evaluate
5. **IF** the formula uses HYPERLINK or WEBSERVICE for egress **THEN** treat data egress on open as the impact, distinct from legacy DDE command execution
6. **IF** the value is also used in a SQL statement **THEN** route to [`sql-injection`](../sql-injection/SKILL.md); the spreadsheet path is separate
7. **IF** a server-side CSV library claims protection **THEN** verify its output bytes rather than trusting the library default
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
9. **IF** every exported cell with a user value is prefixed or quoted so none begins with a trigger **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The same value is reflected into an HTML page | [`cross-site-scripting-stored`](../cross-site-scripting-stored/SKILL.md) | Invariant is browser output encoding, a different sink than a spreadsheet client |
| The value flows into a server-side SQL statement | [`sql-injection`](../sql-injection/SKILL.md) | Invariant is query parameterisation, unrelated to formula evaluation on open |
| Leading whitespace or control characters hide the trigger | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | Routes charset and normalisation tricks that reintroduce a trigger character |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Find every export path and the fields it carries.** Locate CSV and XLSX download endpoints (reports, user lists, audit exports) and map which attacker-writable fields land in which columns; the exporter is the decision point, not the web page.
2. **Classify the exporter's neutralisation.** Determine whether it prefixes a tab or apostrophe, quotes values, tags cell types in XLSX, or writes raw text, because the branch depends on which of these it does.
3. **Write a benign control value and read the exported bytes.** Store a value that starts with a letter, export, and open the file as raw bytes to see exactly how a safe cell is serialised.
4. **Write a probe value beginning with a formula trigger.** Store a value whose first character is `=`, `+`, `-`, or `@` (or a leading tab or carriage return), export again, and read the same cell's raw bytes, changing only the leading character.
5. **Define the differential on the serialised cell.** Compare the probe cell's leading bytes against the control cell's; the signal is the trigger character surviving at the start of the probe cell while the control cell begins with text.
6. **Confirm the client would evaluate it.** The proof is structural in the file, so opening the export in a spreadsheet to see a formula is confirmation of impact but not required to establish the defect.
7. **Stop condition.** Stop when the exported probe cell either (a) begins with a live trigger that disappears once the exporter prefixes or quotes it, (b) is already neutralised for every trigger you try, or (c) would require sending a weaponised WEBSERVICE or DDE formula to a real analyst to show execution. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is the raw exported cell beginning with a formula trigger for attacker input while the control cell does not, plus the exporter line that writes the value without neutralisation. A formula that appears in the web UI but is escaped in the file is not proof.
9. **Close with the structural fix.** Neutralise leading triggers at export time by prefixing an apostrophe or tab, or setting the cell type to text in XLSX, across every exporter, and verify by re-exporting the probe and reading the leading bytes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| An exported CSV cell whose first byte is `=`, `+`, `-`, or `@` from user input | Proves the formula-trigger defect on any spreadsheet client that evaluates leading-operator cells |
| A benign control cell beginning with a letter in the same export | Proves the differential baseline so a trigger cell can be attributed to input, not formatting |
| An exporter that writes raw field text with no prefix or quoting | Proves the neutralisation decision is absent at the export layer on this stack |
| A leading tab or carriage return before an equals sign in a cell | Proves a whitespace-prefixed trigger that several parsers still evaluate on open |
| `=HYPERLINK(` or `=WEBSERVICE(` reaching an exported cell | Proves a data-egress formula class distinct from legacy DDE command execution |
| An XLSX string cell typed as general or shared-string beginning with a trigger | Proves type-tagging did not force text, so the cell can still evaluate in Excel |

## Worked Contrast

**Vulnerable pattern:**

```python
import csv

def export_rows(rows, fh):
    writer = csv.writer(fh)
    writer.writerow(["name", "note"])
    for r in rows:
        # user-controlled 'note' written verbatim; a leading = makes it a formula
        writer.writerow([r["name"], r["note"]])
```

**Hardened pattern:**

```python
import csv

TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

def neutralise(value):
    text = "" if value is None else str(value)
    # Prefix a single quote so a leading trigger is treated as text on open
    return "'" + text if text[:1] in TRIGGERS else text

def export_rows(rows, fh):
    writer = csv.writer(fh)
    writer.writerow(["name", "note"])
    for r in rows:
        writer.writerow([neutralise(r["name"]), neutralise(r["note"])])
```

**Why this matters:** The defective exporter writes user fields verbatim, so a value beginning with an equals sign becomes a live formula when an analyst opens the file; the fixed exporter inspects each cell's first character and prefixes an apostrophe for any formula trigger, forcing the spreadsheet to treat it as text. The control is leading-character neutralisation at the export boundary, applied to every user cell.

## When It Is NOT This Issue

- **Already neutralised cell:** the exporter prefixes a tab or apostrophe, or sets a text cell type, so no user cell begins with a live trigger. A formula string stored in the database that exports as text is not a finding.
- **Value never exported:** a field only shown in the HTML UI and never written to CSV or XLSX has no spreadsheet sink.
- **Internal-only export opened by no client:** a machine-consumed CSV parsed by a program that does not evaluate formulas has no evaluating audience.
- **Trigger only after a safe character:** a cell beginning with a letter or digit, with an equals sign later in the text, is not evaluated as a formula.
- **HTML rendering of the same value:** a leading equals that matters only when reflected into a page is an XSS question, not CSV injection.
- **Export requires the attacker's own account only:** an export only the author can generate and open affects no other user and carries no cross-user impact.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `csv-formula-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `csv-formula-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: csv-formula-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1236 | Mapping: A03:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `csv-formula-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1236`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 22 |
| Distinct dataset sources | 11 |
| Top sources | CYBER_CPT/expku (5), CYBER_CPT/nuclei_templates (4), OffsecCyber (3), hackerone_disclosed_reports (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 7 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
