---
name: ruby-on-rails-security
description: "Audits and hardens Ruby on Rails applications: Strong Parameters (`params.expect`/`permit`), `ActiveRecord` SQL fragments (`order`/`pluck`/`where` string interpolation), `html_safe`/`raw` XSS, `YAML.safe_load`, `send`/`constantize` reflection guards, and Pundit/CanCanCan policy scoping. Use when reviewing Rails code."
family: application-security
tier: leaf
triggers: ["rails security", "strong parameters rails", "constantize rce", "activerecord sql injection", "pundit policy_scope"]
cwe: [CWE-915, CWE-89]
owasp: [A01:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Ruby On Rails Security - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Rails security is mostly a question of whether the framework's opt-in protections were taken up: strong parameters, `policy_scope`, `safe_load`, and hash-form `where`. The framework cannot protect a controller that called `params.permit!`, resolved a record with `find` instead of a scoped relation, or interpolated into `where`. The review therefore walks each controller action for those four decisions and then checks the settings that change them globally.

- **CWE-915 / CWE-89 / CWE-502:** mass assignment, interpolated SQL conditions, and unsafe YAML loading are the recurring Rails classes.
- Rails' own security guides and the `brakeman` rule set remain the reference; treat framework version advisories as patch discipline rather than as a substitute for the review.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the action uses `find` or `find_by` directly **THEN** require a scoped relation (`current_user.invoices.find`) or a Pundit `policy_scope` before the lookup.
2. **IF** the code calls `YAML.load` **THEN** require `safe_load` with `permitted_classes` and `aliases: false`; the unsafe form instantiates arbitrary classes.
3. **IF** the concern is session or credential handling **THEN** open `authentication-and-session-design-review`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate controllers and their actions, including non-RESTful ones.** Rails routes map to actions explicitly; member and collection routes are where authorisation is forgotten because scaffolding does not generate them.
2. **Check the lookup and the parameter filter together.** A scoped lookup with `permit!` still lets the caller set `owner_id`; strong parameters with an unscoped lookup still lets them read another tenant.
3. **Choose the branch on the sink.** `where` takes the hash or placeholder branch; `order` and `select` take the allowlist branch; `render inline:` and `YAML.load` take the removal branch.
4. **Define the baseline-vs-probe differential.** Baseline: the owner updates their record. Probe: a second user submits the same form with the owner's id plus an `owner_id` field, and requests another tenant's record. The hardened build rejects both and leaves `owner_id` unchanged.
5. **State the stop condition and the proof.** Stop when every action has a scoped lookup and an explicit permit list, and both probes fail; proof is the request pair plus the policy or scope location.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `params.permit!` or `permit(:all)` | Proves strong parameters are disabled, so any column including `admin` and `tenant_id` is assignable. |
| `where("... #{params[:q]} ...")` | Proves string interpolation into SQL on ActiveRecord; hash or placeholder form binds. |
| `Invoice.find(params[:id])` with no current_user scope | Proves object-level authorisation is absent on any Rails action. |
| `YAML.load` on an uploaded or posted document | Proves object instantiation from input; `safe_load` with an explicit class list is the inert form. |

## Worked Contrast

**Vulnerable Rails Controller (`params.permit!` + Interpolated `where` + `YAML.load`):**

```ruby
def update
  @account = Account.find(params[:id]) # BUG 1: Unscoped global lookup (IDOR)
  @account.update!(params[:account].permit!) # BUG 2: permit! allows role/admin mass assignment
  Account.where("status = '#{params[:status]}'") # BUG 3: SQL injection in string fragment
  YAML.load(params[:import_yaml]) # BUG 4: Psych arbitrary object deserialization
end
```

**Hardened Rails Controller (Scoped Association + Strong Params + Hash `where` + `safe_load`):**

```ruby
def update
  @account = current_user.accounts.find(params[:id])
  @account.update!(params.require(:account).permit(:display_name, :locale))
  records = current_user.accounts.where(status: params[:status].to_s)
  config = YAML.safe_load(params[:import_yaml].to_s, permitted_classes: [], aliases: false)
  render json: { id: @account.id, count: records.count, keys: config.keys }
end
```

**Why this matters:** Scope lookups through `current_user` / Pundit `policy_scope`, explicitly enumerate Strong Parameters, pass Hash/placeholder bindings to `ActiveRecord`, and enforce `YAML.safe_load`.

## When It Is NOT This Issue

- **`find` on a model with a `default_scope` that scopes by tenant.** The scope is the predicate; verify it exists and is not bypassed with `unscoped`.
- **`permit` with a nested hash for a has-many association.** Nested attributes are intended; the finding is permitting a column the caller should not set.
- **`render inline:` with a constant template string.** No caller data reaches the template source; check the argument's origin before filing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `ruby-on-rails-security` based solely on surface keywords (`params.permit`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ruby-on-rails-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: ruby-on-rails-security
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-915, CWE-89`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ruby-on-rails-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-915, CWE-89`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 1 |
| Top sources | securecode-web (20) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
