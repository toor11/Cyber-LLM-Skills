---
name: nosql-injection
description: "Exploits NoSQL injection in MongoDB, CouchDB, Redis and Elasticsearch: operator injection through JSON and query strings, authentication bypass with $ne and $gt, regex abuse, JavaScript execution in $where, and blind extraction. Use when an application builds NoSQL queries from user input."
family: web-and-application
tier: core
triggers: ["nosql injection", "mongodb injection", "operator injection", "$ne bypass", "nosql"]
cwe: [CWE-943]
owasp: [A03:2021]
attack: []
capec: [CAPEC-66]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Nosql Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The application builds a NoSQL query from user input and the input changes the query's operator structure rather than just its values. In document stores the request body or query string is parsed into a filter object, so a field that should hold a string arrives as {"$ne": null}, {"$gt": ""}, or a $regex and the comparison the developer intended becomes a different operator; in $where or mapReduce a JavaScript string is evaluated, turning the query into code. The security decision is type and operator shaping before the query reaches the engine. The attacker gains authentication bypass, boolean or blind extraction, or server-side JavaScript execution. Confirmation is an operator payload that changes which documents match, reverting when input is coerced to a scalar and operator keys are stripped.

- **Precondition chain:** Request input is parsed into a query object or query-language string without type coercion, operators like $ne, $gt, $regex, or $where survive into the engine, and the match outcome (login, count, timing, or echoed documents) is observable.
- **Readable differential:** The same lookup with a scalar value versus the value replaced by an operator object such as {"$ne": null}; a finding exists when the operator form matches more documents or flips a login, and it reverts when input is cast to a string and operator keys are rejected.
- **Empirical grounding:** CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) sits under OWASP Top 10:2025 A05:2025 Injection; anchored by CVE-2025-23061 (Mongoose $where nested under $or bypassing the earlier CVE-2024-53900 fix, fixed 8.9.5 / 7.8.4 / 6.13.6).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a JSON field that should be a string is accepted as an object like {"$ne": null} **THEN** this is the primary operator-injection case, so establish the scalar-versus-operator differential first
2. **IF** the login filter matches when the password field is {"$gt": ""} **THEN** treat it as an authentication bypass and confirm with a controlled account
3. **IF** a $where or mapReduce string evaluates server-side JavaScript **THEN** prove code reachability with a benign non-blocking expression, never a sleep-style stall on production
4. **IF** only a boolean match or no-match is observable **THEN** build a $regex anchored oracle for character-at-a-time extraction inside authorised scope
5. **IF** the store is Elasticsearch, CouchDB, or Redis rather than MongoDB **THEN** adjust the query grammar (Query DSL, Mango, or command syntax) because operators differ by engine
6. **IF** the injection is really SQL text reaching a relational driver **THEN** switch to [`sql-injection`](../sql-injection/SKILL.md) because the invariant is lexical parsing, not operator shaping
7. **IF** a gateway strips $-prefixed keys before the app parses the body **THEN** record it as a compensating control and test the server-side query builder directly
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** input is coerced to a scalar and operator keys are rejected with no change in matched documents **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Input reaches a relational SQL statement, not a document filter | [`sql-injection`](../sql-injection/SKILL.md) | Invariant is lexical SQL parsing, not NoSQL operator shaping |
| A $where string executes JavaScript on the server | [`code-injection-and-eval`](../code-injection-and-eval/SKILL.md) | Invariant shifts to arbitrary code evaluation, a different sink than query matching |
| The operator payload only re-selects the caller's own documents | [`authorization-and-idor`](../authorization-and-idor/SKILL.md) | Invariant is per-document ownership, an access-control decision |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate the query builder and classify the sink.** Find where request input becomes a filter: a value position in a document filter, an operator-capable object spread into the filter, or a $where or mapReduce JavaScript string, because each needs a different fix.
2. **Name the observable channel.** Login outcome, matched-document count, an echoed document, or timing from a $where loop are four oracles; choose the quietest that can falsify the hypothesis, preferring match-count over timing.
3. **Record a paired baseline.** Send the lookup twice with two scalar values that each match a known number of documents and capture count, status, and any echoed body as the noise floor.
4. **Choose the branch from the channel.** If a login is visible, replace the password with {"$ne": null}; if counts move, compare a true $gt against a false one; if a document is echoed, prepare an anchored $regex oracle; if nothing is observable, stop rather than escalate into $where timing.
5. **Escalate one operator layer at a time.** First prove a scalar becomes an operator object, then a comparison operator, then $regex, and only consider $where when server-side JavaScript is in scope, stopping at the first layer that changes matched documents.
6. **Stop condition.** Halt when the probe either (a) changes which documents match and reverts when input is cast to a scalar and operator keys are stripped, (b) shows no change across two baselines, or (c) would require reading another principal's documents in bulk or evaluating blocking JavaScript on production. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a single-variable differential: identical request, one scalar swapped for an operator object, a reproducible change in matched documents or login outcome, plus the source line where the body is spread into the filter untyped. A parser error alone is not proof.
8. **Close with the structural fix.** Coerce each field to its expected scalar type before building the query, reject objects where a string is expected so user keys cannot be interpreted as operators, disable $where and server-side JavaScript, and replay the scalar-versus-operator pair to confirm matched documents no longer change.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A password field accepted as {"$ne": null} or {"$gt": ""} | Proves operator injection bypassing the login filter on MongoDB or a Mongoose model, not a credential guess |
| A JSON body where a string field arrives as a nested object | Proves the parser preserves operator keys into the filter on document stores like MongoDB and CouchDB |
| Matched-document count changing between a true and false $gt or $lt pair | Proves a boolean oracle where the response body is otherwise stable on any document backend |
| An anchored $regex whose match differs per prefix character | Proves a blind extraction oracle for field contents over NoSQL without reading them directly |
| A $where or mapReduce field evaluating a JavaScript expression | Proves server-side JavaScript execution, the highest-impact NoSQL sink, on MongoDB |
| $where reachable when nested under $or | Proves an operator-nesting bypass of an earlier $where block, as in the Mongoose regression |
| Query-string syntax `field[$ne]=` parsed into an operator | Proves operator injection through URL parameters, not just JSON bodies, on Express and qs-style parsers |

## Worked Contrast

**Vulnerable pattern:**

```javascript
// req.body.username and req.body.password are spread straight into the filter
app.post("/login", async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password,
  });
  res.json({ ok: !!user });
});
```

**Hardened pattern:**

```javascript
app.post("/login", async (req, res) => {
  const username = String(req.body.username ?? "");
  const password = String(req.body.password ?? "");
  // Values are coerced to scalars, so operator objects cannot reach the filter
  const user = await User.findOne({ username }).lean();
  const ok = user ? await verifyHash(password, user.passwordHash) : false;
  res.json({ ok });
});
```

**Why this matters:** The hardened version coerces each field to a string before querying and compares the password against a stored hash rather than matching it in the filter, so a {"$ne": null} or {"$gt": ""} object becomes a literal string and matches nothing. Type coercion plus server-side hash comparison is the structural control; blocklisting $ keys is not.

## When It Is NOT This Issue

- **Scalar-coerced field:** {"$ne": null} appears in the body but the handler casts it to a string first, so it matches nothing; that is the control working.
- **Parser error from a stray operator:** a 500 when $where is sent proves the engine rejected it, not that injection succeeded.
- **Self-scoped match change:** an operator that only re-selects the caller's own documents is not a finding until it returns other principals' documents.
- **Relational backend:** a `' OR 1=1` that works is SQL injection; a NoSQL operator probe failing there is expected, not a non-finding for this skill.
- **Timing on an already-slow aggregation:** a report slow on its own looks $where-injectable; only a delay keyed to the injected expression and reverting when stripped counts.
- **Framework that rejects operator keys:** a stack configured to forbid $-prefixed user keys, such as sanitiser middleware, is protected even though $ne appears in traffic.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `nosql-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `nosql-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: nosql-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-943 | Mapping: A03:2021]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `nosql-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-943`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 43 |
| Distinct dataset sources | 11 |
| Top sources | OffsecCyber (11), CYBER_CPT/hacktricks (7), CYBER_CPT/L5/ctf_search (7), CYBER_CPT/github_security_md (7) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
