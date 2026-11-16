---
name: waf-bypass-and-payload-obfuscation-comment-and-whitespace
description: Comment and whitespace obfuscation. Covers inline comments, newlines, tabs and alternate separators to split keywords and defeat token-based rules. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["comment bypass", "whitespace bypass", "keyword splitting", "sql comment bypass"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-13]
related: [waf-bypass-and-payload-obfuscation, waf-bypass-and-payload-obfuscation-encoding-layers, waf-bypass-and-payload-obfuscation-parser-differentials, waf-bypass-and-payload-obfuscation-rule-specific-evasion]
parent: waf-bypass-and-payload-obfuscation
corpus_sparse: true
---

# WAF Bypass and Payload Obfuscation Comment and Whitespace - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Token-based WAF rules match keywords like UNION, SELECT, or script as contiguous strings, so comment and whitespace obfuscation splits those keywords with sequences the WAF treats as separators but the backend parser treats as nothing. Inline SQL comments, MySQL versioned comments such as a slash-bang block, newline, tab, and form feed break the literal token so the signature never matches, while the database tokenizer discards the comment or whitespace and reconstructs the keyword. The decision point is the mismatch between the WAF tokenizer and the backend lexer: the WAF scans for a literal, the backend lexes the statement. The attacker delivers a blocked keyword past the rule unchanged. Confirmation is the keyword blocked contiguous and allowed-and-parsed when split by a comment or whitespace the backend ignores.

- **Precondition chain:** A token-based rule matches contiguous keywords, the backend parser treats a comment or whitespace sequence as a non-semantic separator, and the split keyword still reaches and is lexed by the backend.
- **Readable differential:** Send a keyword contiguous versus the same keyword split by an inline comment or a newline; a bypass exists when the contiguous form is blocked and the split form reaches and is parsed by the backend, and it closes when the WAF normalizes comments and whitespace before matching.
- **Empirical grounding:** CWE-693 Protection Mechanism Failure and CAPEC-13. The WAFFLED research frames evasion as exploiting parser discrepancies, and this leaf applies the comment-and-whitespace class where the backend tokenizer discards separators the WAF rule treats as literal; the attached grounding note marks it corpus-sparse.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the backend is SQL and the rule matches UNION or SELECT tokens **THEN** split the keyword with an inline comment and confirm the database lexer discards it
2. **IF** the backend is MySQL or MariaDB **THEN** test versioned comments such as a slash-bang block that MySQL executes but a generic rule skips
3. **IF** the sink parses on newlines or tabs **THEN** substitute newline, tab, or form feed for spaces where the rule expects a single space
4. **IF** the keyword can be split by an alternate separator the backend accepts **THEN** test the backend-specific whitespace set rather than only the space character
5. **IF** the target profile is not yet confirmed as a comment or whitespace case **THEN** start at parent class [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) (1 hop)
6. **IF** the evasion really needs encoding layers rather than separators **THEN** switch to [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) (1 hop)
7. **IF** the split payload is blocked in every form and never parsed **THEN** record the control as holding and do not report a bypass
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`waf-and-web-monitoring`](../../../blue-team/detection-and-monitoring/waf-and-web-monitoring/SKILL.md)
9. **IF** the backend does not treat the inserted sequence as a separator **THEN** STOP and classify as a verified non-finding for this evasion class

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The bypass needs multi-layer encoding instead of comments | [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | The evasion dimension is encoding, not separator insertion |
| The real sink is SQL injection reached past the filter | [`sql-injection-waf-tamper-chains`](../sql-injection-waf-tamper-chains/SKILL.md) | The underlying invariant is query parsing, this skill only reaches it |
| The split defeats a WAF rule via container parsing | [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) | The discrepancy is structural parsing, not token splitting |
| Need parent class methodology | [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the rule is token-based and the flaw is real.** Verify the WAF matches contiguous keywords, so a space-separated UNION SELECT is blocked, and that a genuine injection sits behind it, using the sink own benign oracle.
2. **Locate the exact blocked keyword.** Bisect until the single token that triggers the rule is known, so inserted separators can be measured against it.
3. **Record a contiguous-versus-benign baseline.** Capture the block for the contiguous keyword and the pass for a benign request, the two reference points for the differential.
4. **Insert one separator class at a time.** Try an inline comment, then a MySQL versioned comment, then whitespace substitutes such as newline, tab, and form feed inside the keyword, keeping every other byte identical.
5. **Verify the backend reconstructs the keyword.** Confirm with the sink oracle that the database or interpreter lexed the split keyword as the intended token, not as broken text.
6. **Stop condition.** Halt when the keyword is (a) blocked contiguous and parsed when split by a separator the backend ignores, (b) blocked in every separator form, or (c) only provable by a destructive query. Case (a) is a confirmed bypass of this class, (b) means the rule normalizes, (c) is out of scope.
7. **State what counts as proof.** Proof is the identical keyword blocked contiguous and executed by the backend when split by a comment or whitespace, captured as the WAF verdict for each form plus the backend oracle confirming the token lexed. A passed request the backend read as a literal string is not proof.
8. **Close with the structural fix.** Normalize comments and whitespace by stripping inline comments and collapsing separators before signature matching, prefer the backend own parser or a parameterized sink over keyword rules, and treat the signature as defense in depth. Verify by replaying every separator form against the normalizing configuration.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A comment-split UNION SELECT passing where the contiguous form is blocked | Proves the SQL lexer discards the inline comment the WAF rule treated as a separator |
| A MySQL versioned comment executed on the backend but skipped by the rule | Proves the MySQL versioned-comment class that only the backend interprets |
| A keyword split by a newline or tab reaching the backend intact | Proves the rule expected a space while the parser accepts other whitespace |
| Form feed or vertical tab accepted as a separator by the backend | Proves the backend whitespace set is broader than the rule |
| The identical token lexed by the database after separator insertion | Proves the content moved past the filter unchanged, not altered |
| Contiguous keyword blocked and split keyword passed, both to the same sink | Proves the differential is the separator, not the payload |
| Backend-specific comment syntax honored at the sink | Proves which comment dialect the parser accepts for splitting |

## Worked Contrast

**Vulnerable pattern:**

```python
import re

# Token rule matches only contiguous keywords with single spaces
RULE = re.compile(r"union\s+select", re.IGNORECASE)

def blocks(payload):
    # union then an inline comment then select defeats this literal match
    return bool(RULE.search(payload))
```

**Hardened pattern:**

```python
import re

RULE = re.compile(r"union\s+select", re.IGNORECASE)

def blocks(payload):
    # Normalize the way the backend lexer does, then match
    stripped = re.sub(r"/\*.*?\*/", " ", payload, flags=re.DOTALL)
    collapsed = re.sub(r"\s+", " ", stripped)
    return bool(RULE.search(collapsed))
```

**Why this matters:** The defect matches a literal keyword with fixed spacing, so a comment-split or newline-separated form slips through while the database still lexes it as the keyword. The fix removes inline comments and collapses all whitespace before matching, aligning the rule view of the token with the backend lexer so the split forms no longer evade it.

## When It Is NOT This Issue

- **Separator the backend rejects:** inserting a sequence the parser does not treat as whitespace breaks the statement, so a pass is just a syntax error, not a bypass.
- **No injection behind the rule:** splitting a keyword past a filter with no vulnerable sink proves nothing exploitable.
- **Rule already normalizes:** a WAF that strips comments and collapses whitespace before matching is not evaded by these separators.
- **Passed as a literal string:** a search field that stores the split keyword as text never lexes it; confirm execution with the sink oracle.
- **Wrong comment dialect:** using a comment syntax the backend does not honor will not split the token.
- **Monitor-mode or IP control:** the keyword was never blocked, or the block is an IP ban, so there is no token rule to split past.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `waf-bypass-and-payload-obfuscation-comment-and-whitespace` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `waf-bypass-and-payload-obfuscation-comment-and-whitespace` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: waf-bypass-and-payload-obfuscation-comment-and-whitespace
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) - Web and Application (core)
- [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) - Web and Application (leaf)
- [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) - Web and Application (leaf)
- [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](../waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `waf-bypass-and-payload-obfuscation-comment-and-whitespace` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
