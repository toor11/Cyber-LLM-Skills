---
name: ldap-and-xpath-injection-ldap
description: LDAP injection. Covers LDAP filter injection for authentication bypass and directory enumeration, including blind boolean and attribute extraction. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["ldap injection", "ldap filter bypass", "directory enumeration injection"]
cwe: [CWE-90, CWE-643]
owasp: [A03:2021]
attack: []
capec: [CAPEC-136]
related: [ldap-and-xpath-injection, ldap-and-xpath-injection-xpath, sql-injection, cross-site-scripting]
parent: ldap-and-xpath-injection
---

# LDAP and XPATH Injection LDAP - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

LDAP filter injection happens when the application assembles an RFC 4515 search filter by concatenating request input into an expression such as (&(uid=...)(userPassword=...)) and sends it to a directory with a search or bind. The security decision is the filter grammar: unescaped *, (, ), |, &, or a null byte change the filter tree, so a presence match uid=* or an injected )(|( OR clause makes the directory return entries the query never intended. The attacker gains authentication bypass, directory enumeration, or blind attribute extraction. Confirmation depends on the channel the directory leaves open: a bind that flips from failure to success, a change in returned entry count, or a character-at-a-time substring walk against an attribute.

- **Precondition chain:** User input reaches an LDAP filter string without RFC 4515 escaping, the directory performs a search or bind whose outcome the attacker can observe, and no server-side allowlist constrains the attribute or value.
- **Readable differential:** The same lookup with a literal value that matches one entry versus a value carrying a *)( presence or OR clause; a finding exists when the injected filter returns more entries or flips a bind, and it reverts once the metacharacters are escaped server-side.
- **Empirical grounding:** CWE-90 (LDAP Injection) sits under OWASP Top 10:2025 A05:2025 Injection; CVE-2025-48208 (Apache HertzBeat LDAP injection, fixed 1.7.3) is a 2025 instance of unescaped input reaching a directory filter.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match this directory-filter case **THEN** start at parent class [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) (1 hop)
2. **IF** the same endpoint builds an XPath query over an XML store rather than a directory filter **THEN** switch to [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) (1 hop)
3. **IF** an injected `*)(uid=*` flips a login bind from failure to success **THEN** treat it as an authentication-bypass-grade finding and confirm with two controlled accounts
4. **IF** only a boolean entry-count change is observable and no entries are echoed **THEN** drive blind attribute extraction with a `userPassword=a*` presence probe inside authorised scope
5. **IF** the value feeds a distinguished name rather than a search filter **THEN** escape per RFC 4514 DN rules, not RFC 4515 filter rules, because the grammars differ
6. **IF** the directory is Active Directory and the probe touches `objectClass` or `memberOf` **THEN** expect range-limited results and large filters and keep enumeration non-destructive
7. **IF** a web application firewall strips parentheses before the directory parses them **THEN** record the gateway as a compensating control and test the server-side escaper directly
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** input reaches the filter but is escaped or bound to a typed allowlist with no observable differential **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Input reaches an XPath expression over an XML document, not an LDAP filter | [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) | Different interpreter grammar: XPath predicates, not directory filter trees |
| The filter is escaped but the caller still reads entries it should not | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Invariant is per-entry authorisation, not metacharacter neutralisation |
| A wildcard bind lets any password authenticate | [`authentication-bypass`](../authentication-bypass/SKILL.md) | Invariant is the credential check itself, routed to the auth-bypass workflow |
| Need parent class methodology | [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the filter assembly and classify the slot.** Find where request input is concatenated into the RFC 4515 filter or the DN, and label each slot as a filter value, a filter operator position, or a DN component, because each carries a different escape rule.
2. **Name the observable channel before probing.** Decide whether the directory leaks through a bind outcome, a returned entry count, an attribute echoed into the page, or only an error, and pick the quietest channel that can still falsify the hypothesis.
3. **Record a paired baseline.** Issue the lookup twice with two benign values that each match exactly one entry, for example two real usernames, and capture entry count, status, and bind outcome as the noise floor.
4. **Choose the branch from the channel.** If a bind outcome is visible, test a presence filter `*)(uid=*`; if counts move, use a true-versus-false OR clause; if an attribute is reflected, prepare a `userPassword=a*` substring walk; if nothing is observable, stop rather than escalate blindly.
5. **Escalate one grammar element at a time.** Start with a single unescaped `)`, then a presence `*`, then an injected `)(|(` OR branch, stopping at the first element that changes the filter tree, because deeper injection only widens impact, not the finding.
6. **Stop condition.** Halt when the probe either (a) produces an entry-count or bind differential that reverts when the metacharacters are escaped, (b) shows no change across two baselines, or (c) would require reading another principal's attributes such as password hashes. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable differential: identical request, one filter metacharacter added, a reproducible change in returned entries or bind result, plus the source line where the value reaches the filter unescaped. A directory error string alone is not proof.
8. **Close with the structural fix.** Escape every value with an RFC 4515 filter encoder, or an RFC 4514 encoder for DN components, or better bind through a parameterised directory API with a fixed filter template and a server-side allowlist of attribute names, then replay the confirmation pair to confirm the differential is gone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A request value concatenated into `(&(uid=...)(userPassword=...))` | Proves an unescaped filter value slot on any LDAP directory such as OpenLDAP or Active Directory, where metacharacters change the filter tree rather than the data |
| A login that succeeds when the username carries `*)(uid=*` | Proves a presence-match authentication bypass against the bind/search login path, not a password guess |
| Entry count rising when an OR-branch presence clause for objectClass is appended | Proves an injected OR clause widened the search on the directory backend, confirming filter-tree control |
| An attribute value reflected into the page after a `cn=*` presence probe | Proves an enumeration channel that leaks directory attributes on the search endpoint |
| Different responses for `userPassword=a*` versus `userPassword=z*` | Proves a blind substring oracle for character-at-a-time attribute extraction over LDAP |
| Input placed into a distinguished name instead of a filter | Proves a distinct injection point governed by RFC 4514 escaping, not RFC 4515, on directory-backed apps |
| A 500 or invalid-filter error when a lone `(` is sent | Proves the parenthesis reaches the directory parser unbalanced, indicating the escaper is absent |

## Worked Contrast

**Vulnerable pattern:**

```python
import ldap

def login(conn, username, password):
    # Username and password are concatenated straight into the RFC 4515 filter
    flt = "(&(uid=" + username + ")(userPassword=" + password + "))"
    conn.search_s("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, flt)
    return bool(conn.result())
```

**Hardened pattern:**

```python
import ldap
from ldap.filter import escape_filter_chars

ALLOWED_ATTRS = {"uid", "mail"}

def login(conn, username, password, attr="uid"):
    if attr not in ALLOWED_ATTRS:
        raise ValueError("attribute not allowed")
    # Each value is RFC 4515 escaped and the filter template is fixed
    flt = "(&(%s=%s)(userPassword=%s))" % (
        attr, escape_filter_chars(username), escape_filter_chars(password))
    conn.search_s("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, flt)
    return bool(conn.result())
```

**Why this matters:** The hardened version escapes every value with an RFC 4515 encoder and constrains the attribute name to a server-side allowlist, so *, parentheses, and )(|( reach the directory as literal data instead of filter grammar. Password proof should move to a bind rather than a filter match, but the escaping is the structural control.

## When It Is NOT This Issue

- **Escaped filter value:** `*)(uid=*` appears in traffic but the handler runs it through escape_filter_chars, so the directory sees literal characters and the result set never changes. That is the control working.
- **DN escaping mistaken for filter escaping:** input reaches a DN component and is escaped per RFC 4514; a filter metacharacter probe will not apply because the grammar differs.
- **Presence match with no cross-user impact:** a wildcard that only re-selects the caller's own entry is not a finding until it returns entries belonging to other principals.
- **Directory error from malformed input:** a lone `(` that triggers an invalid-filter 500 proves the parser rejected it, not that an injection succeeded.
- **Gateway-stripped parentheses:** a proxy that removes () before the app runs means the probe never reached the filter; test the server-side escaper rather than reporting the block.
- **Operator injection into a non-LDAP interpreter:** a `$ne` or `' or '1'='1` that works is NoSQL or XPath injection, which have their own skills, not CWE-90.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ldap-and-xpath-injection-ldap` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ldap-and-xpath-injection-ldap` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ldap-and-xpath-injection-ldap
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-90, CWE-643 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) - Web and Application (leaf)
- [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ldap-and-xpath-injection-ldap` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-90, CWE-643`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 21 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (12), SecEval/owasp_wstg (2), CYBER_CPT/hacktricks (2), CYBER_CPT/ctf_search (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
