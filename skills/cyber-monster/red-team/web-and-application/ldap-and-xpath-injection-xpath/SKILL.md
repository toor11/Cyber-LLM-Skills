---
name: ldap-and-xpath-injection-xpath
description: XPath injection. Covers XPath query injection to bypass authentication and extract XML nodes, including blind substring-based extraction. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["xpath injection", "xpath bypass", "xml query injection"]
cwe: [CWE-90, CWE-643]
owasp: [A03:2021]
attack: []
capec: [CAPEC-136]
related: [ldap-and-xpath-injection, ldap-and-xpath-injection-ldap, sql-injection, cross-site-scripting]
parent: ldap-and-xpath-injection
---

# LDAP and XPATH Injection XPATH - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

XPath injection happens when the application builds an XPath location path by concatenating request input into an expression such as //user[name/text()='...' and password/text()='...'] evaluated against an XML document or XML database. The security decision is the XPath grammar: an injected ' or '1'='1 closes the string literal and makes the predicate always true, while functions like count(), string-length(), and substring() turn the query into a boolean oracle for blind node extraction. Unlike SQL there are no comments and no privilege model, so the whole document is reachable once a predicate is controllable. Confirmation is a predicate that selects nodes the literal never would: a bypassed login, a changed node count, or a character-at-a-time substring walk.

- **Precondition chain:** Request input is concatenated into an XPath expression without quoting or parameterisation, the expression runs against an XML store whose selection outcome is observable, and no schema or allowlist constrains the value.
- **Readable differential:** The same query with a literal that selects one node versus a value adding ' or '1'='1; a finding exists when the tautology selects more nodes or bypasses a check, and it reverts when the value is passed as a bound XPath variable.
- **Empirical grounding:** CWE-643 (XPath Injection) sits under OWASP Top 10:2025 A05:2025 Injection; SOURCES.md lists no XPath-specific advisory, so this slug stays at the taxonomy level without inventing a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match this XML-predicate case **THEN** start at parent class [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) (1 hop)
2. **IF** the backend is a directory server queried with an LDAP filter rather than an XML document **THEN** switch to [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md) (1 hop)
3. **IF** `' or '1'='1` turns a login predicate always-true and returns a session **THEN** treat it as an authentication bypass and confirm with a second controlled account
4. **IF** only a node-count change is visible **THEN** build a blind oracle with `count(` and `substring(` inside authorised scope
5. **IF** the same parameter is parsed by an XML reader with external entities enabled **THEN** switch to [`xxe`](../xxe/SKILL.md) because the entity parser is a different sink
6. **IF** the document is rendered through an XSLT transform fed by request input **THEN** switch to [`xml-attacks-xxe-and-xslt-xslt-injection`](../xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md)
7. **IF** the engine is XPath 2.0 or 3.1 and `matches()` or `doc()` are available **THEN** note the expanded function set but keep probes non-destructive and off-host
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** input reaches the expression but is passed as a bound variable with no selection differential **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Backend is an LDAP directory, not an XML document | [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md) | Different grammar: LDAP filter parentheses and operators, not XPath predicates |
| The XML parser resolves external entities | [`xxe`](../xxe/SKILL.md) | Invariant is entity expansion in the parser, not predicate structure |
| Request input drives an XSLT stylesheet | [`xml-attacks-xxe-and-xslt-xslt-injection`](../xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) | Invariant is the transform engine, a different XML sink |
| Need parent class methodology | [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the XPath assembly and classify the context.** Find where input is concatenated into the location path and label the context as inside a single-quoted literal, inside a double-quoted literal, or directly in a predicate, because the escape needed differs for each.
2. **Name the observable channel.** Decide whether selection leaks through a login outcome, a node count reflected in the page, a node value echoed, or only an error, and choose the quietest channel that falsifies the hypothesis.
3. **Record a paired baseline.** Run the query with two benign literals that each select exactly one node and capture the node count, status, and any echoed value as the noise floor.
4. **Choose the branch from the channel.** If a login outcome is visible, test the ' or '1'='1 tautology; if counts move, compare a ' and count(/*)=1 and '1'='1 truth pair; if a value is echoed, prepare a substring() oracle; if nothing is observable, stop.
5. **Escalate one predicate element at a time.** Close the literal, add a boolean, then a count() or string-length() function, stopping at the first element that changes the node-set, because deeper extraction only widens impact.
6. **Stop condition.** Halt when the probe either (a) selects more nodes or bypasses a check and reverts when the value is bound as a variable, (b) shows no change across two baselines, or (c) would require extracting another user's credential nodes in full. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable differential: identical request, one quote or boolean added, a reproducible change in the selected node-set, plus the source line where input enters the XPath string. A reflected XML error is not proof on its own.
8. **Close with the structural fix.** Replace string concatenation with a compiled XPath that binds values as variables, for example an XPathExpression with a variable resolver or lxml's xpath(expr, u=value), reject inputs outside a typed allowlist, and replay the confirmation pair to confirm the node-set no longer changes.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Input concatenated into `//user[name='...']` | Proves an unescaped predicate literal on any XPath engine such as lxml, Xerces, or .NET XPathNavigator, where a quote changes node selection |
| A login that succeeds with `' or '1'='1` | Proves a tautology authentication bypass against the XML-backed login predicate, not a credential guess |
| Node count changing with `' and count(/*)=1 and '1'='1` | Proves a boolean oracle over the document structure, confirming predicate control on the XML store |
| Responses differing for `substring(//user[1]/password,1,1)='a'` | Proves a blind substring oracle for character-at-a-time node extraction over XPath |
| An XPath or XML parse error surfaced when a lone `'` is sent | Proves the quote reaches the expression unescaped on the XPath interpreter |
| Use of `doc()` or `document()` accepting a URL | Proves an XPath 2.0 out-of-band fetch surface distinct from in-band node selection |
| Input placed inside a double-quoted literal rather than single | Proves the escape context differs, so a single-quote probe may fail while a double-quote probe succeeds |

## Worked Contrast

**Vulnerable pattern:**

```python
from lxml import etree

def check_login(tree, user, pw):
    # user and pw are concatenated straight into the predicate
    expr = "//user[name/text()='%s' and password/text()='%s']" % (user, pw)
    return tree.xpath(expr)
```

**Hardened pattern:**

```python
from lxml import etree

def check_login(tree, user, pw):
    # Values are bound as XPath variables, never concatenated into the expression
    expr = "//user[name/text()=$u and password/text()=$p]"
    return tree.xpath(expr, u=user, p=pw)
```

**Why this matters:** The hardened version compiles a fixed XPath and binds user and pw as variables, so a quote or an or keyword is treated as literal text inside the node comparison rather than as predicate grammar. Binding variables is the structural control; escaping quotes by hand reintroduces the double-quote context bug.

## When It Is NOT This Issue

- **Bound XPath variable:** ' or '1'='1 appears in traffic but the engine receives it as a $u variable value, so the node-set never grows. The control is working.
- **Reflected XML parse error:** a SAXParseException from a stray quote proves the parser rejected the string, not that a predicate was injected.
- **Wrong quote context:** a single-quote probe that fails may simply sit in a double-quoted literal; absence of a differential for one quote style is not a non-finding until both are tested.
- **Caller-only node selection:** a tautology that only re-selects the caller's own node is not a finding until it returns other principals' nodes.
- **XInclude or entity behaviour:** if the interesting effect is file read via entities, that is XXE, not predicate injection, and belongs to its own skill.
- **Static stylesheet selection:** a hardcoded XPath that never embeds request input is safe even when count() appears in the source.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ldap-and-xpath-injection-xpath` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ldap-and-xpath-injection-xpath` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ldap-and-xpath-injection-xpath
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-90, CWE-643 | Mapping: A03:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`ldap-and-xpath-injection`](../ldap-and-xpath-injection/SKILL.md) - Web and Application (leaf)
- [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ldap-and-xpath-injection-xpath` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-90, CWE-643`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/expku (3), CYBER_CPT/hacktricks (1), CYBER_CPT/github_security_md (1), CYBER_CPT/pentesterlab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
