---
name: sql-injection-waf-tamper-chains
description: SQL injection tamper script chains for WAF bypass. Covers sqlmap tamper composition, comment and encoding layering, keyword splitting, and DBMS-specific tamper selection order for common WAF families. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["sqlmap tamper", "tamper script", "sqli waf bypass", "tamper chain"]
cwe: [CWE-89]
owasp: [A03:2021, A05:2025]
attack: [T1190]
capec: [CAPEC-66]
related: [sql-injection, sql-injection-mysql-variants, sql-injection-mssql-variants, sql-injection-oracle-variants]
parent: sql-injection
---

# Sql Injection WAF Tamper Chains - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)

## Mechanism and Preconditions

A WAF tamper chain exploits a parsing or normalisation gap between the WAF and the backend: the two components disagree on how to decode encodings, whitespace, comments, or case, so a payload the WAF reads as benign is the one the database parses as SQL. Tamper transforms such as comment insertion with `space2comment`, case randomisation with `randomcase`, `between` rewrites, and encoding layers with `charencode` do not change the grammar the database sees; they change the bytes the WAF inspects. The security decision is split across two parsers, and the chain wins when their canonicalisation differs. The underlying injection still lives at the origin, so the WAF is only a compensating control and a bypass proves the control is permeable, not that a new bug class exists.

- **Precondition chain:** A real injection exists at the origin, a WAF sits in front as the compensating control, and the WAF and origin canonicalise some encoding, comment, whitespace, or case construct differently so a transformed payload reaches the parser intact.
- **Readable differential:** The same injection payload raw versus wrapped in a tamper transform; a finding exists when the raw form is blocked with a vendor 403 but the transformed form reaches the origin and reproduces the injection differential, and it closes when the origin itself parameterises the query.
- **Empirical grounding:** CWE-89 under OWASP Top 10:2025 A05:2025 Injection; the WAFFLED research (arXiv 2503.10846) documents container-level parsing discrepancies yielding 1,207 bypasses across AWS, Azure, Cloud Armor, Cloudflare, and ModSecurity, and the 2025 Unicode normalisation bypass class covers full-width, compatibility, and best-fit mappings.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to involve a WAF in path **THEN** start at the parent class [`sql-injection`](../sql-injection/SKILL.md) first (1 hop)
2. **IF** a raw payload is already accepted at the origin with no WAF in path **THEN** treat it as plain injection and return to [`sql-injection`](../sql-injection/SKILL.md); no tamper chain is needed
3. **IF** the WAF and origin disagree on urlencoded versus multipart bodies **THEN** test the body-format differential first, per the WAFFLED class
4. **IF** a Unicode or best-fit normalisation gap is suspected **THEN** read [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) for the normalisation-differential method
5. **IF** the differential is a generic encoding or parser gap beyond SQL **THEN** read [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md)
6. **IF** the backend dialect is known **THEN** select the dialect child such as [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) so tamper choice matches comment and quote syntax
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md)
8. **IF** no origin injection exists behind the WAF **THEN** STOP; a WAF bypass with nothing behind it is not a finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Differential is body format such as urlencoded versus multipart | [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) | The gap is content-type parsing, not SQL grammar |
| Differential is Unicode or best-fit normalisation | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | The invariant is matched normalisation, a charset problem |
| Underlying bug is the origin injection itself | [`sql-injection`](../sql-injection/SKILL.md) | The structural fix is parameterisation, not a better WAF rule |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm an origin injection before testing the WAF.** A tamper chain is meaningless without a real sink, so establish the raw injection differential on a route where the WAF is not in path, or against the origin directly if reachable in scope.
2. **Fingerprint the WAF and its block behaviour.** Record the exact block signature such as a vendor 403 page, a 406, or a challenge, so a bypass is a transition from that signature to an origin response, not just a different error.
3. **Record a three-point baseline.** Capture the benign request, the raw payload that is blocked, and the origin normal response, so the measurement is block versus pass and not pass versus pass.
4. **Target one normalisation axis at a time.** Choose a single transform class per test: comment insertion, case folding, whitespace substitution, encoding layer, or body-format swap. The WAFFLED result shows body-format and encoding interchangeability as the highest-yield axes.
5. **Attribute the pass to the gap, not to payload change.** A transform that passes must still carry the same grammar to the database, so confirm the origin reproduces the original injection differential, proving the WAF and origin canonicalised differently.
6. **Stop condition.** Halt when a transform flips the block signature to a reproduced origin differential, or is blocked identically across every axis, or would require a destructive payload to demonstrate. The first confirms the control is permeable, the second means the control held, the third is out of scope.
7. **State what counts as proof.** Proof is a paired capture: the raw payload returns the vendor block page and the single-transform payload returns the origin injection differential, plus the normalisation axis that differed. A transform that merely returns a different error is not a bypass.
8. **Close with the structural fix.** Parameterise the query at the origin so the injection cannot execute regardless of WAF outcome, and align the WAF to canonicalise bodies, encodings, and Unicode the way the origin does so it stops being the only line of defence. Verify by replaying the raw and transformed payloads against the patched origin.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A vendor 403 for the raw payload but an origin 200 for the same payload in multipart form | Proves a content-type parsing gap per the WAFFLED class, where the WAF and origin read bodies differently |
| `space2comment` or inline `/**/` passing where the raw keyword is blocked | Proves the WAF tokenises on whitespace while the database ignores inline comments, a classic parser differential |
| `randomcase` keywords evading a case-sensitive rule | Proves the WAF rule is case-sensitive while SQL keywords are case-insensitive at the origin |
| Double or mixed percent-encoding decoded once by the WAF and again downstream | Proves a layered-encoding gap where only one component decodes twice |
| A Unicode full-width or best-fit character normalising to a quote at the origin only | Proves a normalisation differential of the class documented for 2025 WAF bypasses |
| `between` rewrites replacing blocked comparison operators | Proves signature matching on literal operators that the rewrite avoids while preserving semantics |
| A transformed payload reproducing the exact origin injection differential | Proves the grammar survived transport, confirming the bypass rather than a benign mutation |

## Worked Contrast

**Vulnerable pattern:**

```python
import re

BLOCK = re.compile(r"(union|select|sleep)", re.IGNORECASE)

def search(cur, request):
    q = request.GET.get("q", "")
    # Denylist is a WAF-style control; a tamper transform slips past it
    if BLOCK.search(q):
        raise ValueError("blocked")
    cur.execute("SELECT id FROM items WHERE name = '%s'" % q)
    return cur.fetchall()
```

**Hardened pattern:**

```python
def search(cur, request):
    q = request.GET.get("q", "")
    # Parameterise at the origin so the query is safe regardless of what the WAF decodes
    cur.execute("SELECT id FROM items WHERE name = %s", (q,))
    return cur.fetchall()
```

**Why this matters:** The defect makes a keyword denylist the real control, which a single tamper transform defeats because the WAF and the parser normalise differently. The fix parameterises at the origin, so the injection cannot execute no matter which encoding or comment form passes the perimeter, leaving the WAF as defence in depth.

## When It Is NOT This Issue

- **Bypass with no sink behind it:** evading the WAF on a route that has no injection is a WAF-tuning note, not an application finding.
- **Different error, not a pass:** a transform that turns a 403 into a 500 at the WAF has not reached the origin parser; only an origin injection differential counts.
- **Scanner noise from blocked payloads:** a flood of 403s proves the WAF is matching, not that a bypass exists.
- **Origin already parameterised:** if the backend binds the value, a payload reaching it changes nothing, so the WAF gap is not exploitable.
- **Transform that breaks the grammar:** an encoding the database also rejects is not a bypass; the payload must still parse at the origin.
- **Rate-limit or challenge page:** a CAPTCHA or throttle response is a control engaging, not a permeable filter.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `sql-injection-waf-tamper-chains` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sql-injection-waf-tamper-chains` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: sql-injection-waf-tamper-chains
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-89 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`sql-injection-mysql-variants`](../sql-injection-mysql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-mssql-variants`](../sql-injection-mssql-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-oracle-variants`](../sql-injection-oracle-variants/SKILL.md) - Web and Application (leaf)
- [`sql-injection-postgres-variants`](../sql-injection-postgres-variants/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sql-injection-waf-tamper-chains` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-89, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 11 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/oxdf (4), OffsecCyber (2), CYBER_CPT/sigmahq (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
