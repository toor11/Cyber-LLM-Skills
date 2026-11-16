---
name: ldap-and-xpath-injection
description: Injects into LDAP filters and XPath queries to bypass authentication and enumerate directory or XML data. Use when a login or search feature queries a directory service or XML store with string-concatenated filters.
family: web-and-application
tier: leaf
triggers: ["ldap injection", "xpath injection", "directory injection", "filter injection", "ldap bypass"]
cwe: [CWE-90, CWE-643]
owasp: [A03:2021]
attack: []
capec: [CAPEC-136]
related: [ldap-and-xpath-injection-ldap, ldap-and-xpath-injection-xpath, sql-injection, cross-site-scripting]
---

# LDAP and XPATH Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A login or search feature builds an LDAP filter or an XPath expression by concatenating user input into the query string, so metacharacters in the input change the structure of the query rather than acting as a value. In LDAP, characters like the parentheses, the asterisk, and the boolean operators &, |, and ! let an attacker close the intended clause and add their own, turning (uid=x) into a tautology or a wildcard that returns every entry or bypasses an authentication filter. In XPath, quotes and operators like or, together with position and string functions, rewrite the node test the same way, with no dialect-specific terminator required. The decision point is whether input reaches the filter as structure or only as an escaped value. The attacker gains authentication bypass or directory and XML enumeration. A non-destructive probe compares a benign value against a metacharacter value and watches the match set change.

- **Precondition chain:** User input is concatenated into an LDAP filter or XPath expression, the characters that alter filter or expression structure are not escaped, and a feedback channel (login success, result-set size, or an error) reveals the structural change.
- **Readable differential:** A benign username versus one carrying a filter-breakout sequence such as *)(uid=*: only the second widens or short-circuits the query, and the effect disappears once the value is passed through escapeFilterChars-style neutralization or a parameterized query API.
- **Empirical grounding:** CWE-90 (LDAP Injection) and CWE-643 (XPath Injection) under OWASP Top 10:2025 A05 Injection. CVE-2025-48208 (Apache HertzBeat LDAP injection, fixed 1.7.3) anchors the LDAP side; SOURCES.md lists no XPath-specific advisory, so the XML-query side stays at CWE-643 taxonomy level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the backend is a directory service queried with LDAP filters **THEN** switch to [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md) (1 hop)
2. **IF** the backend is an XML store queried with XPath **THEN** switch to [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) (1 hop)
3. **IF** a login or search parameter is concatenated into the filter without escaping **THEN** treat the filter-construction site as the sink
4. **IF** the query targets a document database with operator syntax **THEN** switch to [`nosql-injection`](../nosql-injection/SKILL.md) (1 hop)
5. **IF** the directory is reached through a JNDI lookup URI **THEN** switch to [`jndi-injection`](../jndi-injection/SKILL.md) (1 hop)
6. **IF** the backend is a relational database with SQL grammar **THEN** switch to [`sql-injection`](../sql-injection/SKILL.md) (1 hop)
7. **IF** the filter is built with parameterized APIs or escapeFilterChars-style neutralization **THEN** verify the escaping covers parentheses, asterisk, backslash, and NUL before concluding
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** user input reaches the directory only through bound, escaped value slots **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The query targets a document database with operator syntax | [`nosql-injection`](../nosql-injection/SKILL.md) | Invariant is operator and type injection in a document store, not filter metacharacters |
| The directory is reached through a JNDI lookup URI | [`jndi-injection`](../jndi-injection/SKILL.md) | Invariant is naming-service lookup destination, not filter construction |
| The backend is a relational database with SQL grammar | [`sql-injection`](../sql-injection/SKILL.md) | Invariant is SQL lexical parsing, not LDAP or XPath filter grammar |
| Target matches `ldap-and-xpath-injection-ldap` | [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ldap-and-xpath-injection-xpath` | [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the filter or expression construction site.** Find where a login or search parameter is concatenated into an LDAP filter string or an XPath expression. Classify the backend as a directory (LDAP) or an XML store (XPath). The construction site is the sink.
2. **Identify the feedback channel.** Determine whether login success or failure, result-set size, or an engine error reveals a structural change. This selects the least intrusive oracle before any probe.
3. **Record a benign baseline.** Submit a normal username or search term and capture the authentication result and the number of entries returned. This is the control the probe must diverge from.
4. **Send a structure-changing differential.** For LDAP, submit a value carrying a parenthesis and a wildcard such as *)(uid=*; for XPath, submit a value with a quote and an or clause. A match set that widens or a login that succeeds only for the metacharacter value proves the input is parsed as structure.
5. **Confirm the sink with a neutralization check.** Submit a value with a single literal metacharacter and observe whether it is escaped (safe no-match) or alters the filter (error or wildcard). This isolates whether escaping is applied.
6. **Stop condition.** Halt when the probe (a) changes the match set or auth result and reverts once the value is escaped or bound, (b) leaves the result unchanged across two baselines, or (c) would require extracting real directory or XML records beyond a count. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a differential tied to one changed value, a reproducible change in match-set size or authentication outcome, plus the exact concatenation line where the metacharacter reaches the filter unescaped. An LDAP or XPath error string alone is not proof unless driven by attacker input.
8. **Close with the structural fix and verify.** Escape metacharacters with escapeFilterChars (or the XPath equivalent) or use a parameterized query API that places input only in value slots, then replay the benign and breakout values to confirm only the benign one matches.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A login or search parameter concatenated into an LDAP filter string | Proves the filter-construction sink on a directory-backed stack, the entry condition for LDAP injection |
| A filter-breakout value such as *)(uid=* widening or short-circuiting the query | Proves input is parsed as filter structure rather than a value, confirming LDAP injection |
| A password field carrying ' or '1'='1 turning an XPath node test always-true | Proves XPath expression structure is attacker-controllable on an XML-backed login |
| A directory search returning the entire subtree for one request | Proves the injected wildcard widened the result set, an enumeration oracle |
| XPath engine errors on malformed expressions tied to a search parameter | Proves the input reaches the expression compiler unescaped |
| Input passed through escapeFilterChars or a parameterized query API | Proves metacharacter neutralization is present, a working control rather than a finding |

## Worked Contrast

**Vulnerable pattern:**

```python
import ldap3

def find_user(conn, username):
    # Username concatenated into the filter: *)(uid=*) rewrites the query
    flt = f"(&(objectClass=person)(uid={username}))"
    conn.search("ou=people,dc=example,dc=com", flt)
    return conn.entries
```

**Hardened pattern:**

```python
import ldap3
from ldap3.utils.conv import escape_filter_chars

def find_user(conn, username):
    safe = escape_filter_chars(username)  # parentheses, asterisk, backslash, NUL hex-escaped
    flt = f"(&(objectClass=person)(uid={safe}))"
    conn.search("ou=people,dc=example,dc=com", flt)
    return conn.entries
```

**Why this matters:** escape_filter_chars neutralizes the LDAP metacharacters so the username can only land in the value slot, never add a new (uid=*) clause that turns the AND filter into a wildcard or bypass. The input becomes data, not structure.

## When It Is NOT This Issue

- **escapeFilterChars or a parameterized API in use:** metacharacters are neutralized, so input lands only in a value slot and cannot alter the filter.
- **Hardcoded filter with no user input:** a static search filter that interpolates no request value has no injection surface.
- **Error or wildcard behavior from a legitimate value:** a username that genuinely contains a parenthesis, handled safely, is not an injection.
- **Caller-only directory scope:** a query that can reach only the caller's own entry, with no cross-user data or auth bypass, is not impactful.
- **SQL or document-store backend mistaken for a directory:** a $ne or UNION probe that works indicates NoSQL or SQL injection, a different invariant.
- **Bind account least-privileged and read-scoped:** enumeration limited to non-sensitive attributes by directory ACLs reduces this below a finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ldap-and-xpath-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ldap-and-xpath-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ldap-and-xpath-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-90, CWE-643 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md) - Web and Application (leaf)
- [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ldap-and-xpath-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-90, CWE-643`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 29 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (13), SecEval/owasp_wstg (5), CYBER_CPT/hacktricks (4), cyber-security/security-code (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
