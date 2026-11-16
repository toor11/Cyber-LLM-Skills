---
name: express-and-fastify-security
description: "Audits and hardens Node.js Express and Fastify services: middleware ordering bypasses, JSON-schema body validation (blocking prototype pollution and NoSQL `$ne` operator objects), `path.resolve` root confinement, `child_process.execFile` vs `exec`, and rate/body-size caps. Use when reviewing Node.js backends."
family: application-security
tier: core
triggers: ["express security", "fastify security", "nodejs code review", "execfile vs exec", "nosql object guard"]
cwe: [CWE-1321, CWE-78]
owasp: [A05:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Express and Fastify Security - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Express and Fastify are middleware pipelines, so their security properties are ordering properties: which parser ran, whether a schema validated the body, whether the error handler leaked a stack, and whether a route was mounted before the auth guard. Node adds two specific hazards - JSON bodies that become operator objects for MongoDB, and prototype-chain writes during merges or `qs`-style parsing - plus the request-body decompression surface that body-parser owns by default.

- **CWE-1321 / CWE-78 / CWE-943:** prototype pollution, shell interpretation, and NoSQL operator injection are the three recurring classes on this stack.
- body-parser below 2.4.0 (or 1.20.9) carries CVE-2026-111181: a compressed request body followed by trailing bytes crashes the process with one unauthenticated request; the interim control is `inflate: false`.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the service accepts `application/json` into a Mongo query **THEN** require a schema that pins each field to a primitive; an operator object such as `{"$ne": null}` must fail validation, not reach the driver.
2. **IF** the service accepts compressed bodies **THEN** check body-parser and Node versions together, since the Brotli decoder fix is in the runtime.
3. **IF** the finding is authorisation on a route **THEN** verify middleware order, because a guard registered after `express.json()` still runs after the body is parsed and may be skipped by error paths.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Dump the middleware stack in registration order.** Express applies `app.use` in order and routers mount their own chains; a guard inside one router does not cover another. Fastify's hook order is `onRequest`, `preParsing`, `preValidation`, `preHandler`, and a guard in the wrong hook sees an unvalidated body.
2. **Check every body-consuming route for a schema.** Fastify needs `schema.body` with `additionalProperties: false`; Express needs an explicit validator because JSON parsing accepts any shape.
3. **Choose the branch by sink.** Database values take a schema-plus-driver-cast branch; shell calls take the `execFile` argv branch; filesystem paths take a resolved-prefix branch; outbound URLs take an allowlist branch.
4. **Define the baseline-vs-probe differential.** Baseline: a well-formed login body. Probes: an operator object in the password field, a `__proto__` key, and a gzip body with trailing bytes. Each must be rejected with a validation error, not a 200 and not a process exit.
5. **State the stop condition and the proof.** Stop when every route has a schema and the three probes are rejected by validation; proof is the probe responses plus the middleware registration order.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `req.body.password` passed straight into `findOne` | Proves NoSQL operator injection on any Node/Mongo service; the JSON parser turns `$ne` into an operator. |
| `exec(` with a template literal, or `execSync` with interpolation | Proves shell interpretation; `execFile` with an argv array is the inert form on Node. |
| `Object.assign({}, defaults, req.body)` or a recursive merge | Proves prototype pollution when `__proto__` is present, which can flip authorisation defaults. |
| `bodyParser.json()` with default `inflate` on body-parser below 2.4.0 | Proves the CVE-2026-111181 crash path is reachable before routing and before authentication. |

## Worked Contrast

**Vulnerable Express Handler (NoSQL Operator Object + Shell `exec` + Unchecked `path.join`):**

```javascript
app.post('/api/login-export', async (req, res) => {
  // BUG 1: req.body.password = {"$ne": null} bypasses MongoDB login when JSON body is unvalidated
  const user = await db.collection('users').findOne({ email: req.body.email, password: req.body.password });
  // BUG 2: path.join('/exports', '../../etc/passwd') escapes root; exec() spawns /bin/sh!
  const out = path.join('/var/exports', req.body.filename);
  exec(`gzip -c ${out}`, (err, stdout) => res.send(stdout));
});
```

**Hardened Schema-Validated Handler (Primitive Types + Root Confinement + `execFile`):**

```javascript
const LoginExportSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
  filename: z.string().regex(/^[a-zA-Z0-9_-]+\.csv$/),
}).strict();

app.post('/api/login-export', async (req, res) => {
  const { email, password, filename } = LoginExportSchema.parse(req.body);
  const user = await db.collection('users').findOne({ email: String(email) });
  if (!user || !(await argon2.verify(user.passwordHash, password))) return res.sendStatus(401);
  const root = path.resolve('/var/exports');
  const target = path.resolve(root, filename);
  if (!target.startsWith(root + path.sep)) return res.sendStatus(400);
  execFile('gzip', ['-c', target], { timeout: 5000 }, (err, stdout) => res.send(stdout));
});
```

**Why this matters:** Enforce strict JSON schemas (`additionalProperties: false` / `.strict()`) to block `$ne` objects and `__proto__` keys, verify `path.resolve` prefix confinement, and use `execFile` argument arrays instead of `exec`.

## When It Is NOT This Issue

- **`express.json()` with `strict: true` and a schema validator behind it.** The pair closes both operator objects and type confusion; do not file on the parser alone.
- **`exec` with a constant command and no interpolation.** No caller data reaches the shell; the style note is separate from a finding.
- **A `qs` advisory Express cannot trigger.** Express calls `qs.parse`, and the 2026 `qs` advisories affect `stringify` options Express never sets; bump for scanner hygiene, not as a live finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `express-and-fastify-security` based solely on surface keywords (`child_process.execFile`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `express-and-fastify-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: express-and-fastify-security
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-1321, CWE-78`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `express-and-fastify-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1321, CWE-78`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 1 |
| Top sources | securecode-web (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
