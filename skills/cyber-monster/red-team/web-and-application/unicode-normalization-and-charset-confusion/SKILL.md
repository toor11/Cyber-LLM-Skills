---
name: unicode-normalization-and-charset-confusion
description: Audits Unicode normalization (NFKC/NFKD), case-mapping collisions (Kelvin sign, dotless i), and charset/Jackson hex-cast parser differentials that bypass WAFs, email domain checks, or identifier uniqueness. Use when user strings cross normalization or transcoding layers.
family: web-and-application
tier: leaf
triggers: ["unicode normalization bypass", "nfkc collision", "case mapping bypass", "charset confusion", "jackson hex cast"]
cwe: [CWE-176, CWE-179]
owasp: [A03:2021]
attack: []
capec: []
related: [sql-injection, cross-site-scripting, csrf, ssrf]
corpus_sparse: true
---

# Unicode Normalization and Charset Confusion - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A normalization or charset-confusion flaw exists when two layers disagree about the canonical form of a string: a validator checks the raw bytes while a downstream sink normalizes them, so a value that looks safe at the filter becomes something else at the sink. Unicode compatibility normalization (NFKC or NFKD) folds characters such as the fullwidth solidus into ASCII, case folding maps the Kelvin sign U+212A to lowercase k and the dotless i across locales, and best-fit mapping in legacy encoders turns exotic code points into ASCII during transcoding. The decision point is the order, which CWE-179 names early validation before normalization. An attacker submits a value that passes an allowlist, host check, or uniqueness constraint yet canonicalizes to a forbidden or colliding value at the database, filesystem, or WAF. Confirmation is a single value accepted by validation but equal to a different, sensitive value after normalization at the sink.

- **Precondition chain:** A string crosses at least two layers that normalize differently, validation runs on the pre-normalization form, and the post-normalization form at the sink differs in a security-relevant way.
- **Readable differential:** Submit a crafted code point versus its ASCII canonical form; a finding exists when the crafted form passes validation but the sink treats it as the ASCII form, and it closes when validation normalizes to the same canonical form before deciding.
- **Empirical grounding:** CWE-176 Improper Handling of Unicode Encoding and CWE-179 Incorrect Behavior Order: Early Validation, under OWASP Top 10:2025 A05:2025 Injection as a canonicalization flaw. The Unicode normalization bypass class covering compatibility forms, case folding, and best-fit mapping is described in the OWASP Global AppSec USA 2025 talk and the Synacktiv Sec-T 2025 paper.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the validator checks raw bytes but the sink applies NFKC or NFKD **THEN** submit a compatibility character that folds to an ASCII character the validator would have rejected
2. **IF** the check is case-insensitive via simple lowercasing **THEN** test case-folding collisions such as U+212A Kelvin to k or the dotless i across locales
3. **IF** a legacy transcoding step applies best-fit mapping **THEN** submit a code point that best-fit maps to an ASCII metacharacter at the sink
4. **IF** the backend is a Jackson or similar parser doing a hex or numeric cast **THEN** test the charset or hex-cast parser differential where the parser reads a different value than validation
5. **IF** the value is a hostname, email domain, or fetch target **THEN** check whether normalization changes the host the fetch resolves to and read [`ssrf`](../ssrf/SKILL.md) for the resolver gap
6. **IF** the value is a path or filename **THEN** check whether normalization reintroduces traversal and read [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md)
7. **IF** the normalization defeats a WAF rule rather than business logic **THEN** treat it as filter evasion and read [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md)
8. **IF** the collision affects username or identifier uniqueness **THEN** test whether two canonically distinct inputs map to the same stored identifier
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
10. **IF** validation and the sink already normalize to the same form before deciding **THEN** STOP and classify as a verified non-finding for CWE-176

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Normalization reintroduces a traversal sequence after a path check | [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) | The sink is filesystem path resolution, a traversal invariant |
| The canonical form changes the resolved host of a fetch | [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) | The disagreement is parser-versus-resolver, an SSRF allowlist invariant |
| Normalization is used only to slip a rule past the WAF | [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | The target is the filter container, not the business-logic canonical form |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the two layers and their normalization steps.** Find where validation runs (regex, allowlist, uniqueness check) and where the sink canonicalizes (database collation, filesystem, `unicodedata.normalize`, Java Normalizer, a transcoding gateway), and note the order per CWE-179.
2. **Classify the normalization class in play.** Decide whether the gap is compatibility folding (NFKC or NFKD), case folding (Kelvin sign, dotless i, sharp s), or best-fit and charset mapping, because the candidate characters differ per class.
3. **Record a canonical baseline.** Submit the plain ASCII value and capture how both the validator and the sink treat it, establishing the intended canonical form.
4. **Pick a character from the class and probe the gap.** Submit a code point the validator sees as non-matching but that normalizes at the sink to the sensitive ASCII form, for example a fullwidth or compatibility variant or U+212A for k.
5. **Show the value changes between layers.** Demonstrate that the accepted input is one string at validation and a different string at the sink, which is the whole flaw.
6. **Stop condition.** Halt when the input either (a) passes validation and canonicalizes to a different, sensitive value at the sink and reverts when validation normalizes first, (b) is treated identically by both layers, or (c) would require corrupting real records to prove. Case (a) confirms CWE-176 and CWE-179, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is one value that validation accepts and the sink canonicalizes to a different value, captured as the raw code points, the validator verdict, and the normalized sink form, reverting when both normalize to the same form first. A mojibake display glitch is not proof.
8. **Close with the structural fix.** Normalize to a single canonical form, typically NFKC, at the trust boundary before validating, apply case folding consistently with a locale-independent mapping, forbid mixed-script or compatibility characters where identifiers must be unique, and validate the post-normalization value. Verify by replaying the crafted code point against the normalize-then-validate build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A fullwidth or compatibility character accepted by a regex but folded to ASCII at the sink | Proves an NFKC or NFKD gap where validation precedes normalization per CWE-179 |
| U+212A Kelvin sign treated as distinct by the check but lowercased to k downstream | Proves a case-folding collision on any case-insensitive comparison |
| A best-fit mapped code point becoming an ASCII metacharacter after transcoding | Proves a charset best-fit gap introduced by a legacy encoder |
| A Jackson or JSON parser hex or numeric cast yielding a different value than validated | Proves the charset and hex-cast parser differential at the deserialization boundary |
| Two canonically distinct usernames mapping to one stored identifier | Proves a uniqueness-constraint collision from inconsistent normalization |
| Validation on the raw string and the sink calling a normalize routine | Proves the order defect directly in source regardless of payload |
| A host or path that changes after normalization versus before | Proves the canonical form reaching the resolver or filesystem differs from the validated one |

## Worked Contrast

**Vulnerable pattern:**

```python
import unicodedata

ALLOWED = {"transfer", "profile"}

def route_action(action):
    # Validation runs on the raw string, before normalization (CWE-179)
    if action not in ALLOWED:
        raise ValueError("action not allowed")
    # The sink normalizes, so a compatibility variant that passed now folds in
    return dispatch(unicodedata.normalize("NFKC", action))
```

**Hardened pattern:**

```python
import unicodedata

ALLOWED = {"transfer", "profile"}

def route_action(action):
    # Normalize first, then validate the canonical form the sink will use
    canonical = unicodedata.normalize("NFKC", action)
    if canonical not in ALLOWED:
        raise ValueError("action not allowed")
    return dispatch(canonical)
```

**Why this matters:** The defect validates the raw input and normalizes afterward, so a compatibility character that is not in the allowlist as raw bytes passes the check and then folds to a different value at the sink. The fix normalizes to NFKC first and validates the exact string the sink will act on, so the check and the sink agree.

## When It Is NOT This Issue

- **Both layers normalize identically:** when validation and the sink apply the same NFKC form before deciding, a compatibility character is folded before the check and cannot smuggle a different value.
- **Display-only mojibake:** garbled rendering from a charset mismatch that never changes a security decision is a presentation bug.
- **No second layer:** a value validated and stored verbatim with no downstream normalization has no gap to exploit.
- **Pure encoding, not normalization:** a percent-encoding or base64 trick belongs to the encoding-layers filter-evasion skill, not Unicode normalization.
- **Collision without impact:** two inputs folding to the same value where uniqueness is not security-relevant is harmless.
- **Locale-independent folding already applied:** a check using casefold with a fixed locale closes the Kelvin and dotless-i cases.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `unicode-normalization-and-charset-confusion` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `unicode-normalization-and-charset-confusion` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: unicode-normalization-and-charset-confusion
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-176, CWE-179 | Mapping: A03:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `unicode-normalization-and-charset-confusion` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-176, CWE-179`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
