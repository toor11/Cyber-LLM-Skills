---
name: cross-site-scripting-stored
description: Stored cross-site scripting. Covers persistent XSS through profiles, comments, filenames, metadata, admin dashboards, support tickets and any second-order render path. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["stored xss", "persistent xss", "second order xss", "stored cross site"]
cwe: [CWE-79]
owasp: [A03:2021, A05:2025]
attack: [T1059]
capec: [CAPEC-63]
related: [cross-site-scripting, cross-site-scripting-reflected, cross-site-scripting-dom, cross-site-scripting-mutation]
parent: cross-site-scripting
---

# Cross Site Scripting Stored - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

Stored XSS persists an attacker value in a datastore and re-emits it into a later page rendered for other users, so the parse-and-execute happens on a different request and often a higher-privileged audience such as an admin dashboard. The security decision is output encoding at every render path that reads the field, not validation at write time; storing quotes intact is irrelevant if any reader emits them as markup. The attacker gains script execution in the viewing user's session wherever the stored field is shown. Confirmation ties the injected field to a specific render path and proves that path emits it without context encoding.

- **Precondition chain:** an attacker-writable field is persisted verbatim, at least one later render path emits that field into an HTML or script context without context-aware encoding, and a different user or the attacker in another session loads that path.
- **Readable differential:** a benign stored value versus a stored value carrying the single delimiter that breaks the viewing context; a finding exists when the rendered page parses the delimiter as new markup on the read path, and it closes when that render path context-encodes the field.
- **Empirical grounding:** CWE-79 covers this class in its persistent, second-order form; OWASP Top 10:2025 folds cross-site scripting into A05:2025 Injection. SOURCES carries no stored-specific CVE, so the anchor stays at the CWE-79 / OWASP taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to be persisted plus a second-order render **THEN** start at parent class [`cross-site-scripting`](../cross-site-scripting/SKILL.md) (1 hop)
2. **IF** the field renders in an admin or moderation dashboard a privileged user opens **THEN** prioritise that render path, since the audience makes the impact account-takeover-grade
3. **IF** the value is echoed back only on the submitter's immediate response **THEN** route to [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) because the render path is immediate
4. **IF** the stored value is injected by client-side JavaScript reading an API response **THEN** route to [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md), where the sink is a DOM write
5. **IF** the stored field is a filename, email, or metadata rendered in another view **THEN** enumerate every secondary render path before concluding
6. **IF** a CSP blocks inline execution on the viewing page **THEN** route to [`csp-and-security-header-bypass`](../csp-and-security-header-bypass/SKILL.md) to test policy gadgets
7. **IF** an HTML sanitizer runs on output and you suspect re-parsing **THEN** route to [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`waf-and-web-monitoring`](../../../blue-team/detection-and-monitoring/waf-and-web-monitoring/SKILL.md)
9. **IF** the field is context-encoded on every discovered render path **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Value is echoed only on the submitter's immediate response | [`cross-site-scripting-reflected`](../cross-site-scripting-reflected/SKILL.md) | Invariant is encoding on the immediate echo, not a stored second-order path |
| Stored value is emitted by client-side JavaScript from an API | [`dom-based-vulnerabilities`](../dom-based-vulnerabilities/SKILL.md) | Sink is a browser DOM API, so encoding must be client-side |
| A sanitizer rewrites the stored HTML on output | [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) | Risk is re-serialisation mutation, not raw emission of the stored field |
| Need parent class methodology | [`cross-site-scripting`](../cross-site-scripting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate write-then-read pairs, not pages.** For each attacker-writable field (profile name, comment, filename, ticket body, metadata) list every later page or widget that renders it; the render path, not the input form, is the sink.
2. **Choose the highest-value read path first.** A field re-shown in an admin dashboard or moderation queue executes in a privileged session, so pick that audience as the branch because it defines impact.
3. **Store a benign tracer.** Persist a unique inert marker and confirm which render paths display it and in what context (HTML text, attribute, script), with no breaking characters yet.
4. **Store the paired probe.** In a second record change only the one delimiter that breaks the context the tracer landed in, keeping the rest identical, then load the read path.
5. **Compare the two rendered pages.** The probe record should yield a new DOM node or attribute on the viewing page while the tracer record stays inside its node.
6. **Attribute the encoding gap to a layer.** Confirm the storage kept the delimiter intact and which template on the read path emitted it raw, so input-side validation is not mistaken for the control.
7. **Stop condition.** Stop when the stored probe either (a) parses as markup on a render path and reverts to inert text once that path context-encodes the field, (b) is encoded on every render path across two stored records, or (c) would require a real other user to load the page to demonstrate cross-user impact. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is the stored field rendering as attacker-controlled markup in a viewer's session on a named read path, plus the exact template that emits the field without context encoding. A stored value that round-trips with quotes intact but renders encoded is not proof.
9. **Close with the structural fix.** Context-encode the field on every render path and prefer an auto-escaping template, not only where it was first displayed, and verify by reloading each read path with the delimiter probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A unique stored tracer reappearing on a different page than where it was set | Proves a second-order render path exists on any persisted-data stack, where the read path is the real sink |
| The same stored field rendered inside an admin or moderation dashboard | Proves a privileged-audience render path where execution lands in a higher-trust session |
| Stored delimiter characters surviving into the viewing page un-encoded | Proves the read-path template omits context encoding, independent of input validation |
| A field accepted and stored verbatim with quotes and angle brackets intact | Proves input validation is not the control, since only output encoding on read closes it |
| Filenames, display names, or metadata rendered in both list and detail views | Proves multiple render paths for one field, each needing its own encoding on this stack |
| A CSP header on the viewing page alongside an un-encoded stored field | Proves execution may hinge on a CSP gadget, so impact depends on policy bypassability |
| An output-time HTML sanitizer applied to the stored field | Proves the risk may shift to sanitizer re-parsing rather than raw emission of the field |

## Worked Contrast

**Vulnerable pattern:**

```python
def render_comments(db, post_id):
    rows = db.comments.for_post(post_id)   # body stored verbatim at write time
    items = ["<li>" + row.body + "</li>" for row in rows]
    return "<ul>" + "".join(items) + "</ul>"
```

**Hardened pattern:**

```python
from markupsafe import escape

def render_comments(db, post_id):
    rows = db.comments.for_post(post_id)
    # Context-encode each stored body on the read path, every time it is rendered
    items = ["<li>{}</li>".format(escape(row.body)) for row in rows]
    return "<ul>" + "".join(items) + "</ul>"
```

**Why this matters:** The defective read path concatenates stored comment bodies into HTML, so a body saved with a tag executes for every viewer; the fixed path HTML-entity-encodes each body as it is rendered, so the same stored value shows as inert text. The control lives on every render path, not at the write form.

## When It Is NOT This Issue

- **Stored but encoded on read:** the field is persisted with markup intact yet every render path entity-encodes it, so viewers see text. Verbatim storage is not the finding.
- **Self-only render:** the stored value is shown only back to its author in their own session with no other audience, so cross-user impact is absent.
- **Preview-only, never persisted:** a live preview that reflects the field in the editor without saving is reflected behaviour, not a stored second-order path.
- **Admin-authored content:** a field only a trusted admin can write and that renders to admins is a trust-boundary question, not attacker-controlled stored XSS.
- **Encoded API then safe DOM write:** the field is returned JSON-encoded and the client sets it via textContent, which is safe handling rather than stored XSS.
- **Sanitizer strips on write:** a server-side HTML sanitizer removes active markup before storage, so the stored bytes are already neutralised on every read.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cross-site-scripting-stored` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cross-site-scripting-stored` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cross-site-scripting-stored
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
- [`cross-site-scripting-dom`](../cross-site-scripting-dom/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-mutation`](../cross-site-scripting-mutation/SKILL.md) - Web and Application (leaf)
- [`cross-site-scripting-filter-and-context-bypass`](../cross-site-scripting-filter-and-context-bypass/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cross-site-scripting-stored` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-79, T1059`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 47 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (26), hackerone_disclosed_reports (12), bugbounty-hunter-v1 (4), cyber-security/security-code (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
