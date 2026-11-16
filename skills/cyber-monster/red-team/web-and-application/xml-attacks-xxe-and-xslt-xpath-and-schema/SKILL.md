---
name: xml-attacks-xxe-and-xslt-xpath-and-schema
description: XPath and XML schema attacks. Covers XPath query injection, schema poisoning, and XML parser features like XInclude and DTD-based denial of service. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["xpath injection", "xml schema attack", "xinclude", "billion laughs"]
cwe: [CWE-611, CWE-643]
owasp: [A05:2021]
attack: []
capec: [CAPEC-221]
related: [xml-attacks-xxe-and-xslt, xml-attacks-xxe-and-xslt-xslt-injection, sql-injection, cross-site-scripting]
parent: xml-attacks-xxe-and-xslt
---

# Xml Attacks XXE and Xslt XPATH and Schema - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

XPath injection happens when an application builds an XPath expression by pasting input into the query text, so a value meant to match a node instead rewrites the predicate that selects nodes. The decision point is the XPath string construction: because XPath has no privilege model, a predicate that becomes always-true returns every node, which can bypass an authentication lookup or read sibling records the query never intended. The schema and DTD side of this leaf is different in kind: a grammar that declares nested entities forces the parser to expand them geometrically, consuming memory and CPU, and XInclude offers a non-entity way to pull in resources. Proof for the query case is a node set that flips between a true and a false predicate; proof for expansion is parse time that scales with a bounded nesting depth.

- **Precondition chain:** Input is concatenated into an XPath expression or into a DTD or schema the parser expands, the XPath has no variable binding or the expansion has no depth limit, and the resulting node set or parse behaviour is observable to the caller.
- **Readable differential:** The query is run with a false predicate versus an always-true predicate; a finding exists when the true form returns nodes the false form does not, and it reverts once the value is bound as an XPath variable.
- **Empirical grounding:** CWE-643 XPath injection and CWE-776 XML entity expansion anchor this leaf under OWASP Top 10:2025 A05 Injection; SOURCES.md has no XPath-specific or schema-specific advisory, so this stays at taxonomy rather than naming a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed as XPath or schema abuse **THEN** start at the parent class [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) (1 hop) for general triage
2. **IF** input is concatenated into an XPath predicate **THEN** confirm with a true-versus-false predicate pair before anything else
3. **IF** the XPath runs against an authentication document **THEN** test whether a tautology returns a privileged node, with two accounts to confirm
4. **IF** the parser expands nested internal entities **THEN** measure parse time for a small bounded expansion against baseline rather than escalating depth
5. **IF** the schema or parser allows XInclude **THEN** check whether xi:include pulls a benign marker resource into the tree
6. **IF** the engine is XPath 2.0 or 3.1 with function support **THEN** enumerate the functions that widen the query before deeper probing
7. **IF** the query is actually LDAP rather than XPath **THEN** route to [`ldap-and-xpath-injection-ldap`](../ldap-and-xpath-injection-ldap/SKILL.md)
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** input is bound as an XPath variable and expansion is capped **THEN** STOP and record a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The query targets a directory service | [`ldap-and-xpath-injection-xpath`](../ldap-and-xpath-injection-xpath/SKILL.md) | The dedicated XPath-injection sibling carries directory semantics this leaf does not |
| The payload is really an external entity read | [`xxe-file-disclosure`](../xxe-file-disclosure/SKILL.md) | Entity file read is a different invariant than XPath neutralisation |
| Nested entity expansion causes denial of service | [`xxe`](../xxe/SKILL.md) | Entity-expansion availability failure is handled by the entity parent |
| Need parent class methodology | [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the XPath construction or the schema expansion point.** Find where input enters the expression string or where the parser reads a DTD or schema, and decide which of the two invariants is in play.
2. **Read the binding and limit configuration.** Determine whether the XPath uses variable binding and whether the parser enforces an entity-expansion depth or size limit, because these settings decide exploitability.
3. **Record the baseline node set or parse time.** Run the query with a legitimate value and capture the normal result, or time a benign document, so the differential has a reference.
4. **Choose the branch from the sink.** If a predicate accepts input, use a boolean pair; if the grammar accepts declarations, use a small bounded nested entity; do not mix the two probes in one request.
5. **Apply the non-destructive differential.** For XPath send a true predicate and a false predicate and compare node counts; for expansion raise nesting a few bounded levels and compare parse time, never to the point of exhausting the host.
6. **Stop condition.** Halt when the probe either (a) flips the node set for the true predicate or scales parse time with bounded depth and reverts when bound or capped, (b) shows no change, or (c) would require reading real credential nodes or exhausting the server. Case (a) is the finding, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a reproducible node-set flip between a true and false predicate tied to one input, or a parse-time curve that tracks bounded nesting, plus the unbound concatenation or missing limit in source; a single error is not proof.
8. **Close with the structural fix.** Bind every XPath value as a variable through a compiled expression, and cap entity expansion with external and parameter entities disabled. Verify by replaying the predicate pair and the bounded document against the fixed build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A predicate node set that grows for `' or '1'='1` and empties for `' or '1'='2` | Proves XPath injection where input controls the predicate on any XML-backed query |
| An authentication XPath returning a user node for a tautology input | Proves an auth-bypass via always-true predicate, the high-impact XPath case |
| Parse time rising geometrically with nested-entity depth | Proves unbounded entity expansion in the DTD handler, a denial-of-service invariant distinct from injection |
| An xi:include element resolving a resource into the result tree | Proves XInclude is honoured, a non-entity inclusion path on libxml-based parsers |
| A schema import URL fetched during validation | Proves schema resolution reaches the network, expanding the validation surface |
| Distinct results for equivalent values that differ only by a quote | Proves the quote broke out of the literal into the expression context |
| An XPath 2.0 function such as `doc()` available in the expression | Proves a richer engine whose functions widen beyond node selection |

## Worked Contrast

**Vulnerable pattern:**

```python
from lxml import etree


def find_user(doc, name, pw):
    tree = etree.fromstring(doc)
    # Credentials are concatenated straight into the XPath predicate, so a
    # tautology rewrites which nodes are selected.
    q = "//user[name/text()='%s' and pw/text()='%s']" % (name, pw)
    return tree.xpath(q)
```

**Hardened pattern:**

```python
from lxml import etree


def find_user(doc, name, pw):
    tree = etree.fromstring(doc)
    # Values are bound as XPath variables, so input stays data and can never
    # alter the predicate structure.
    q = etree.XPath("//user[name/text()=$n and pw/text()=$p]")
    return q(tree, n=name, p=pw)
```

**Why this matters:** The defect concatenates the credential into the XPath text, so `' or '1'='1` turns the predicate always-true and returns a privileged node. The structural control compiles the expression once and binds the values as variables, so the attacker's quote is treated as a literal and cannot change the query shape.

## When It Is NOT This Issue

- **Bound XPath variable:** an expression that binds values through a compiled XPath with variables cannot be restructured by input, even when the raw string reaches the engine.
- **Static expression:** a query assembled only from server constants with no input in the predicate is not injectable.
- **Expansion already capped:** a parser that enforces an entity-depth or size limit and rejects the nested document is enforcing the control, so the timing probe is a non-finding.
- **Quote rejected before the query:** input that is escaped or validated so the quote never reaches the expression context is safe regardless of what the raw value looks like.
- **LDAP filter mistaken for XPath:** a `*)(uid=*` style payload that works is directory-filter injection, which belongs to the LDAP sibling, not this leaf.
- **Result identical for true and false predicates:** if the node set does not change between the tautology and the contradiction, the input is not reaching the predicate structure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `xml-attacks-xxe-and-xslt-xpath-and-schema` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `xml-attacks-xxe-and-xslt-xpath-and-schema` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: xml-attacks-xxe-and-xslt-xpath-and-schema
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-611, CWE-643 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`xml-attacks-xxe-and-xslt`](../xml-attacks-xxe-and-xslt/SKILL.md) - Web and Application (leaf)
- [`xml-attacks-xxe-and-xslt-xslt-injection`](../xml-attacks-xxe-and-xslt-xslt-injection/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `xml-attacks-xxe-and-xslt-xpath-and-schema` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-611, CWE-643`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 27 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/osv (11), OffsecCyber (8), CYBER_CPT/pentesterlab (2), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 12 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
