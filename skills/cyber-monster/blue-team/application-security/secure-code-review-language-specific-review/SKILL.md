---
name: secure-code-review-language-specific-review
description: "Language specific secure review. Covers language and framework specific pitfalls: deserialization, template use, framework auth middleware and ORM misuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: application-security
tier: leaf
triggers: ["language security review", "framework pitfall", "orm injection review"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, secure-code-review-injection-and-data-flow, secure-code-review-access-control-review, threat-modeling]
parent: secure-code-review
---

# Secure Code Review Language Specific Review - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **leaf** | Paired Counterpart: [`codeql-query-development`](../../../red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md)

## Mechanism and Preconditions

Every language has a small set of constructs where the runtime does something the source does not advertise: Ruby's `YAML.load` instantiating arbitrary classes, Python's `pickle` executing on load, Java's reflection during deserialisation, JavaScript's prototype chain during a recursive merge, Go's `os.Root` versus a resolved path, and PHP's `unserialize` magic methods. The review enumerates those constructs per language, then checks whether attacker-influenced data reaches them. It is a checklist review, and the checklist is language-versioned.

- **CWE-502 (Deserialization of Untrusted Data)** is the dominant class here, alongside CWE-1321 for prototype pollution and CWE-22 for path handling.
- The dangerous form changes across versions; `YAML.safe_load` and `yaml.load(..., Loader=SafeLoader)` are both safe, `YAML.load` is not.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is whether a flow is reachable at all **THEN** use `secure-code-review-injection-and-data-flow`; this sibling assumes reachability and focuses on the language construct.
2. **IF** the language is a framework being reviewed as a whole **THEN** use the framework sibling (Django, Rails, Spring, Express, ASP.NET Core, Go), which names the framework's own helpers.
3. **IF** the construct is a template engine **THEN** check sandbox configuration, since engine defaults differ by version.
4. **IF** the target narrows to `secure-code-review` **THEN** open [`secure-code-review`](../secure-code-review/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`secure-code-review`](../secure-code-review/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Build the construct list for the language and version in use.** For each: the dangerous form, the safe form, and what the runtime does that makes it dangerous. Record the version, because several defaults changed.
2. **Search for the dangerous form by AST or semantics, not by substring.** A regex for `eval` matches `evaluate_field`; a rule should match the call target and argument shape.
3. **Choose the branch by what the construct can reach.** Deserialisation and template compilation reach code execution; path handling reaches files; prototype manipulation reaches authorisation logic; each branch has a different inert form.
4. **Define the baseline-vs-probe differential.** Baseline: the construct receives a value the application produced. Probe: it receives a value with the language's marker (a `!!ruby/object`, a `__proto__` key, a pickle opcode). The finding stands when the probe changes behaviour rather than raising a handled error.
5. **State the stop condition and the proof.** Stop when every construct on the list has either a safe form or a documented reason it is unreachable; proof is the call site plus the probe result.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `YAML.load` on request data in Ruby | Proves object instantiation from input on the Ruby runtime; `YAML.safe_load` with permitted classes is the inert form. |
| `pickle.loads` on a queue message in Python | Proves code execution at load time; a JSON schema or a signed envelope is the inert form. |
| Recursive merge of a JSON body into a config object in JavaScript | Proves prototype pollution when the merge walks `__proto__`; `Object.create(null)` and an explicit key allowlist are inert. |
| `filepath.Join(base, userInput)` in Go | Proves traversal because `Join` cleans but does not confine; `os.Root` (Go 1.24+) or a resolved prefix check is the inert form. |

## Worked Contrast

**Vulnerable per-language constructs (Ruby YAML load, JS recursive merge):**

```ruby
class ImportController < ApplicationController
  def create
    payload = YAML.load(params[:bundle])          # instantiates arbitrary classes
    Setting.merge!(payload['settings'])
    head :ok
  end
end

# javascript equivalent in the same service:
function merge(target, src) {
  for (const k in src) { target[k] = typeof src[k] === 'object' ? merge(target[k] || {}, src[k]) : src[k] }
  return target
}
```

**Fixed per-language constructs (permitted classes, null-prototype merge):**

```ruby
class ImportController < ApplicationController
  PERMITTED = [Symbol]
  def create
    payload = YAML.safe_load(params[:bundle], permitted_classes: PERMITTED, aliases: false)
    Setting.merge!(payload.fetch('settings').slice('theme', 'locale', 'timezone'))
    head :ok
  end
end

# javascript:
function merge(target, src) {
  const out = Object.assign(Object.create(null), target)
  for (const k of Object.keys(src)) {
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue
    const v = src[k]
    out[k] = v && typeof v === 'object' && !Array.isArray(v) ? merge(out[k], v) : v
  }
  return out
}
```

**Why this matters:** The Ruby call deserialises arbitrary classes from a request parameter, which is remote code execution through the object graph. The JavaScript merge walks inherited keys and writes through the prototype chain, which is how an attacker sets `isAdmin` on every object. The fixed forms whitelist classes, drop aliases, slice the accepted keys, and merge into a null-prototype object while refusing the three dangerous key names.

## When It Is NOT This Issue

- **`YAML.safe_load` with an explicit `permitted_classes` list.** Safe for those classes; only file if the list includes something with dangerous initialisers.
- **`pickle` over a signed, internal cache.** The bytes are not attacker-supplied; check the signing key scope before filing.
- **`eval` in a build script or test helper.** Not reachable from untrusted input; note it as hygiene, not a vulnerability.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secure-code-review-language-specific-review` based solely on surface keywords (`deserialization`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-code-review-language-specific-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secure-code-review-language-specific-review
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`codeql-query-development`](../../../red-team/security-assessment-tooling-and-automation/codeql-query-development/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`secure-code-review-injection-and-data-flow`](../secure-code-review-injection-and-data-flow/SKILL.md) - Application Security (leaf)
- [`secure-code-review-access-control-review`](../secure-code-review-access-control-review/SKILL.md) - Application Security (leaf)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-code-review-language-specific-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctf_search (3), CYBER_CPT/awesome_web_security (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
