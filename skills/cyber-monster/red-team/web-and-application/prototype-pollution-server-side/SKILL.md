---
name: prototype-pollution-server-side
description: Server-side prototype pollution. Covers Node merge and clone sinks, pollution through query parsers and JSON bodies, and detection via reflection or side effects. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["server side prototype pollution", "node prototype pollution", "merge pollution"]
cwe: [CWE-1321]
owasp: [A08:2021]
attack: []
capec: [CAPEC-460]
related: [prototype-pollution, prototype-pollution-client-side-gadgets, prototype-pollution-rce-chains, sql-injection]
parent: prototype-pollution
---

# Prototype Pollution Server Side - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

The server-side variant pollutes Object.prototype inside a long-lived Node process. Request pipelines parse JSON bodies, qs or querystring nested keys, or multipart fields into plain objects and feed them to a deep-merge, clone, or path-set helper that walks __proto__ or constructor.prototype. Because the process persists, the polluted default survives across requests and users until restart, so later handlers reading an unset option such as a view engine setting, an isAdmin flag, or spawn options silently inherit the attacker value. The security decision is the merge that fails to reject the special keys. Detection is by reflection, where an echoed object now carries the key, or by a server side effect such as a status or behaviour change.

- **Precondition chain:** an untrusted body or query is parsed into nested objects, a merge, clone, or path-set helper assigns those keys without a prototype guard, Object.prototype is mutable in the process, and a subsequent handler reads an attribute it never explicitly set.
- **Readable differential:** issue the __proto__.<probe> body then a second unrelated request; server-side pollution is proven when the second response reflects or acts on <probe> despite never setting it, and it clears when the merge rejects the prototype keys.
- **Empirical grounding:** This maps to CWE-1321 under OWASP Top 10:2025 A08 Software or Data Integrity Failures; SOURCES.md has no server-side prototype-pollution advisory, so grounding stays at the CWE-1321 taxonomy without a CVE.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target is not yet confirmed to walk nested keys server-side **THEN** start at parent class [`prototype-pollution`](../prototype-pollution/SKILL.md) (1 hop) to confirm a recursive sink exists
2. **IF** the sink is body-parser JSON merged into a config or options object **THEN** probe __proto__ in the JSON body and read an independent endpoint for persistence
3. **IF** the entry point is qs or querystring building nested objects from bracket keys **THEN** test a[__proto__][x] against the parser output on the server
4. **IF** the sink is a lodash merge, defaultsDeep, or a clone helper **THEN** confirm the exact version, since some releases guard merge against __proto__
5. **IF** a polluted key can set a value that later throws when read **THEN** test a denial-of-service default such as a key read on every request path
6. **IF** a polluted option can reach child_process or a template compiler **THEN** switch to [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) (1 hop)
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no merge or path-set walks nested keys and config uses null-prototype objects **THEN** STOP and classify as a verified non-finding

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| A polluted option reaches child_process or a template compiler | [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) | Execution gadget, a different invariant than the prototype write |
| Pollution flips an authorization default the handler reads | [`authorization-and-idor-property-level`](../authorization-and-idor-property-level/SKILL.md) | Impact is a property-level access decision, not prototype mutation itself |
| A polluted key sets an object property the app trusts as config | [`http-parameter-pollution-and-mass-assignment`](../http-parameter-pollution-and-mass-assignment/SKILL.md) | Unauthorized property assignment invariant, distinct from the shared prototype write |
| Need parent class methodology | [`prototype-pollution`](../prototype-pollution/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. Locate the parse-to-merge pipeline: body-parser, qs, or a multipart handler feeding a merge, clone, or path-set helper.
2. Pick a canary property the application never sets and record a clean second request before polluting.
3. Send the __proto__.<canary> body through the sink, keeping the value inert.
4. Verify persistence with an independent request on a fresh connection, because server-side pollution survives across requests until restart.
5. Identify which key form took effect, __proto__ or constructor.prototype, to characterize the gap precisely.
6. Define the baseline-versus-probe differential: an unrelated endpoint reflects or acts on the canary only after the probe and reverts once the merge is guarded.
7. **Stop condition.** Stop when (a) an independent request reflects the attacker canary, proving process-global pollution, (b) no independent request leaks it across both forms, or (c) proving further would destabilize the production process; (a) is confirmation, (b) is a non-finding, (c) is out of scope.
8. **State what counts as proof.** Proof is a second, unrelated request reflecting or acting on an attribute the attacker set through __proto__, reverting when prototype keys are rejected. Close with guarding the keys, using Object.create(null), schema-validating the body, freezing Object.prototype, and re-running the independent-request probe.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| body-parser output passed to _.merge(config, req.body) | Proves a server write sink where request JSON reaches a recursive merge |
| qs parsing a[__proto__][x] into a nested object | Proves pollution through the query parser, a source distinct from the JSON body |
| A canary surviving into an unrelated later request | Proves process-global persistence rather than a per-request own-property set |
| constructor.prototype accepted after __proto__ is filtered | Proves an incomplete blocklist on this server stack |
| A polluted admin or isAdmin default read by a handler | Proves an authorization side effect flowing from the shared prototype |
| A 500 'x is not a function' after a pollution request | Proves a denial-of-service primitive where a polluted key breaks a read path |

## Worked Contrast

**Vulnerable pattern:**

```javascript
const _ = require("lodash");
const config = { role: "user" };

app.post("/settings", (req, res) => {
  _.merge(config, req.body);        // __proto__ in the body mutates Object.prototype
  res.json({ saved: true });
});
app.get("/me", (req, res) => res.json({ admin: ({}).isAdmin === true }));
```

**Hardened pattern:**

```javascript
const _ = require("lodash");

app.post("/settings", (req, res) => {
  const clean = JSON.parse(JSON.stringify(req.body), (k, v) =>
    (k === "__proto__" || k === "constructor" || k === "prototype") ? undefined : v);
  const config = Object.assign(Object.create(null), { role: "user" });
  _.merge(config, clean);           // dangerous keys stripped before merge
  res.json({ saved: true });
});
app.get("/me", (req, res) => res.json({ admin: ({}).isAdmin === true }));
```

**Why this matters:** The defect merges the raw body into a shared object, so a __proto__ key reaches Object.prototype and ({}).isAdmin flips for every subsequent request. The fix strips prototype keys during a reviver pass and merges into a null-prototype object, so no request can mutate the shared prototype.

## When It Is NOT This Issue

- **Null-prototype config:** a config object built with Object.create(null) cannot inherit a polluted prototype property.
- **Guarded merge version:** a lodash release whose merge rejects __proto__ is not a server write sink.
- **Self-scoped object:** a merge into a per-request object that no later handler reads has no cross-request effect.
- **Reflection without persistence:** an echo that returns input but does not survive into an independent request is not pollution.
- **Schema-validated body:** a strict schema that rejects unknown keys blocks __proto__ before the merge.
- **Map-based store:** configuration held in a Map has no prototype chain to tamper with.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `prototype-pollution-server-side` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `prototype-pollution-server-side` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: prototype-pollution-server-side
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1321 | Mapping: A08:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`prototype-pollution`](../prototype-pollution/SKILL.md) - Web and Application (core)
- [`prototype-pollution-client-side-gadgets`](../prototype-pollution-client-side-gadgets/SKILL.md) - Web and Application (leaf)
- [`prototype-pollution-rce-chains`](../prototype-pollution-rce-chains/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `prototype-pollution-server-side` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1321`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/gh_advisories (12), CYBER_CPT/osv (5), CYBER_CPT/gh_security_lab (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 11 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
