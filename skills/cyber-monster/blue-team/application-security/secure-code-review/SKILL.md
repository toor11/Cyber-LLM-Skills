---
name: secure-code-review
description: "Reviews source code for security defects: data flow tracing from source to sink, authentication and authorization checks, crypto misuse and injection classes across languages. Use when reviewing application code."
family: application-security
tier: flagship
triggers: ["secure code review", "code audit", "source review", "sast review"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review-injection-and-data-flow, secure-code-review-access-control-review, secure-code-review-language-specific-review, threat-modeling]
---

# Secure Code Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **flagship** | Paired Counterpart: [`codeql-query-development`](../../../red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md)

## Mechanism and Preconditions

A code review finding is a reachability claim: a specific untrusted entry point, a specific interpreter sink, and a witness path that reaches the sink without passing the predicate that would make the input inert. The review therefore works from the framework's own defaults (router binding, ORM parameterisation, template autoescaping, cookie flags) so you can tell whether a control is explicit in the diff, implicit in the framework, or simply absent. Anything you cannot walk end to end stays a question for the author, not a finding.

- **CWE-20 (Improper Input Validation):** the defect is a missing or misordered predicate at a sink, not the mere presence of user data.
- Review scope is one commit range plus the deployment config it assumes; a finding that depends on an unread config file is a conditional finding and must say so.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the diff adds a route, resolver, Server Action, or message consumer **THEN** enumerate it as an entry point first; authorisation that lives only in a parent middleware is a claim to verify, not a control to assume.
2. **IF** the sink is a SQL string, template source, shell argv, filesystem path, or outbound URL **THEN** record which parameterisation or allowlist applies, and cite the file:line where it runs.
3. **IF** the codebase is a single framework (Django, Rails, Spring, Express, ASP.NET Core, Go) **THEN** read the framework-specific sibling instead of re-deriving its defaults here.
4. **IF** the target narrows to `secure-code-review-injection-and-data-flow` **THEN** open [`secure-code-review-injection-and-data-flow`](../secure-code-review-injection-and-data-flow/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
5. **IF** the target narrows to `secure-code-review-access-control-review` **THEN** open [`secure-code-review-access-control-review`](../secure-code-review-access-control-review/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
6. **IF** the target narrows to `secure-code-review-language-specific-review` **THEN** open [`secure-code-review-language-specific-review`](../secure-code-review-language-specific-review/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `secure-code-review-injection-and-data-flow` | [`secure-code-review-injection-and-data-flow`](../secure-code-review-injection-and-data-flow/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `secure-code-review-access-control-review` | [`secure-code-review-access-control-review`](../secure-code-review-access-control-review/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `secure-code-review-language-specific-review` | [`secure-code-review-language-specific-review`](../secure-code-review-language-specific-review/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate entry points from the framework's routing table, not from grep.** List every handler that binds request data (path params, query, body, headers, cookies, queue messages) and the middleware chain that runs before it.
2. **Classify each sink by which interpreter consumes the string.** SQL, template source, shell, filesystem, deserialiser, and outbound HTTP each have a different inert form; a sanitiser for one class is irrelevant to the next.
3. **Choose the branch on how the control is expressed.** Explicit in this hunk, inherited from a framework default you can name, or absent. Only the third is a finding; the second is a finding only if a later config override disables the default.
4. **Build the baseline-vs-probe differential.** Baseline: the same request with a benign value. Probe: a value that must change behaviour only if the predicate is missing (a second tenant's identifier, a quote, a `../`, a scheme change). Stop when the probe returns the baseline response, which proves the control held.
5. **State what counts as proof and record the non-findings.** Proof is a file:line for the sink, the predicate that should have run, and the request that reaches it; then list the sinks you cleared so the author does not remove working protection.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `request.args` flowing into `QuerySet.extra()` or `RawSQL` | Proves an f-string or `%` splice reached the SQL text on Django; the ORM's parameter binding is bypassed only when the identifier itself is interpolated. |
| `@app.route` handler with no `Depends`/`before_request` on the object fetch | Proves authentication without object authorisation on Flask/FastAPI; the token proves identity, the missing owner predicate is the defect. |
| `exec`/`execSync` with a template literal built from request data | Proves shell interpretation of user data on Node; `execFile` with an argv array is the inert form, `exec` with a string is not. |
| `ObjectInputStream.readObject` on a request body | Proves a deserialisation sink reachable pre-auth on the JVM; a typed allowlist (`BasicPolymorphicTypeValidator`) or a non-serialised format is the only structural fix. |

## Worked Contrast

**Vulnerable Pattern (Django/DRF - allowlist written as a loop over request keys):**

```python
class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer

    def get_queryset(self):
        qs = Invoice.objects.all()                      # tenant scope never applied
        for key in self.request.query_params:           # caller chooses the columns
            qs = qs.filter(**{key: self.request.query_params[key]})
        return qs
```

**Fixed / Hardened Pattern (closed filter map plus tenant predicate):**

```python
_FILTERS = {"status": "status", "issued_after": "issued_at__gte"}

class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer

    def get_queryset(self):
        qs = Invoice.objects.filter(tenant_id=self.request.user.tenant_id)
        for key, column in _FILTERS.items():
            value = self.request.query_params.get(key)
            if value is not None:
                qs = qs.filter(**{column: value})
        return qs
```

**Why this matters:** The first version passes caller-chosen keys into `filter()`, so `?tenant_id=2` widens the result set and traverses a relation in one request; the second binds both the column set and the tenant predicate before the caller is consulted.

## When It Is NOT This Issue

- **Owner predicate enforced by a queryset manager or RLS policy.** `filter(**kwargs)` is safe when the key set is closed by an upstream serializer and the manager already scopes by tenant; check the manager before filing.
- **Sink unreachable from request data.** A `RawSQL` call whose arguments come only from settings or migrations is a code-quality note, not an injection finding.
- **Sanitiser is structural, not textual.** `shlex.quote` in front of `shell=True`, or `html.escape` in front of an HTML attribute context, does not clear the finding; `subprocess.run([...])` and context-aware autoescaping do.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secure-code-review` based solely on surface keywords (`source to sink`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-code-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secure-code-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`codeql-query-development`](../../../red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review-injection-and-data-flow`](../secure-code-review-injection-and-data-flow/SKILL.md) - Application Security (leaf)
- [`secure-code-review-access-control-review`](../secure-code-review-access-control-review/SKILL.md) - Application Security (leaf)
- [`secure-code-review-language-specific-review`](../secure-code-review-language-specific-review/SKILL.md) - Application Security (leaf)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-code-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 26 |
| Distinct dataset sources | 8 |
| Top sources | securecode-web (16), ctf-solver-dataset (2), hackerone_disclosed_reports (2), CYBER_CPT/nuclei_templates (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
