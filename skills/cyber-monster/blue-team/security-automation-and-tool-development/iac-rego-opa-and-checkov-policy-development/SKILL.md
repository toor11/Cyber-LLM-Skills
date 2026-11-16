---
name: iac-rego-opa-and-checkov-policy-development
description: "Writes Policy-as-Code rules in Open Policy Agent Rego v1 (`conftest` / OPA) and custom Checkov `BaseResourceCheck` Python/YAML checks over Terraform `tfplan.json`, Kubernetes manifests, and Dockerfiles: enforcing encryption, private networking, least-privilege IAM, and pinned container digests with unit tests (`opa test`). Use when codifying cloud/IaC guardrails."
family: security-automation-and-tool-development
tier: core
triggers: ["opa rego policy", "conftest terraform", "custom checkov check", "opa test rego", "tfplan security"]
cwe: [CWE-1188]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Iac Rego OPA and Checkov Policy Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

A Terraform plan is a document of intent, not of state: each `resource_changes[]` entry carries `address`, `type`, `change.actions`, `change.after` (the values Terraform already knows), and `change.after_unknown` (attributes whose value only exists after apply, marked `true`). A policy that only reads `after` silently passes every resource whose security-relevant attribute is still unknown — and unknown is the common case for provider-computed fields such as `encrypted` or `arn`. The correct shape is a three-way test: is this a change we care about (`create`, `update`, replacement rather than pure `delete`), is the attribute literal and acceptable in `after`, and is it explicitly unknown in `after_unknown` rather than absent. Rego v1 makes the third clause fragile in a specific way — `after_unknown` may be `null`, and `object.get(null, ...)` fails at runtime, so the access must be guarded by `is_object`. Checkov covers the same ground for pre-plan source config and for frameworks without a plan, through a `BaseResourceCheck` subclass whose `scan_resource_conf` returns `CheckResult.PASSED`/`FAILED`/`SKIPPED`.

- **CWE-1188 (Initialization of a Resource with an Insecure Default):** a guardrail that passes because the field was unknown at plan time leaves the insecure default to be applied.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are writing a Rego guardrail over `terraform show -json` output **THEN** start from `import rego.v1`, use `deny contains msg if { ... }`, and gate on `actions in {"create","update"}` while ignoring pure `["delete"]`.
2. **IF** a checked attribute could be provider-computed **THEN** test it in three steps — `is_object(rc.change.after_unknown)` first, then membership in `after_unknown` as unknown, then the literal value in `after` — never a bare `object.get` on a possibly-null object.
3. **IF** you need a check for source config rather than a plan (or a framework with no plan) **THEN** subclass `BaseResourceCheck` with `name`, `id`, `supported_resources`, and `categories`, and run it with `checkov --external-checks-dir <dir> --check <ID>`; the directory needs an `__init__.py`.
4. **IF** the question is about detection content rather than infrastructure policy **THEN** use [`sigma-pipeline-and-backend-development`](../sigma-pipeline-and-backend-development/SKILL.md); Rego is not a detection language.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `iac-rego-opa-and-checkov-policy-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable policy and test shapes | [`QUERIES.md`](QUERIES.md) | `conftest`/`opa` invocations, fixture plans, Checkov commands |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `opa`, `conftest`, `checkov` flags and version pins |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Unknown-attribute and delete-path incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Change-freeze handoff while a guardrail is corrected |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Open Policy Agent Rego v1 (`import rego.v1`, `deny contains msg if`, `terraform show -json` with `create`/`update`/replacement + `is_object` `after_unknown` guard) + Checkov `BaseResourceCheck` Python custom policies
- **Mandatory Self-Validation Command:** `opa check --strict policy.rego; opa test -v .`

1. **Confirm the inputs.** Establish which artifact the policy reads (plan JSON, source `.tf`, Kubernetes manifest, Dockerfile), the Terraform `format_version` in the fixtures, and which attributes the provider computes rather than accepts. Confirm the gate's severity mapping so a `deny` actually blocks the pipeline.
2. **Choose the branch.** Plan-based guardrail → Rego over `resource_changes`. Source-config or cross-resource logic that needs a parser per framework → Checkov custom check. Both are legitimate; picking the wrong one produces a policy that cannot see the field it tests.
3. **Define how to validate the policy.** `opa check --strict` for syntax, then `opa test -v` over fixture plans that cover four cases: a failing resource, a passing resource, a resource whose attribute is unknown, and a pure delete. `conftest test` then runs the same policy against the same fixtures in the CI shape.
4. **Name the stop condition.** Stop when a policy passes a resource whose security attribute is in `after_unknown` (fail-open), when a pure delete is reported as a violation (noise that trains reviewers to ignore the gate), when `after` is `null` and the rule dereferences it, or when a `test_` rule is missing for a new branch.
5. **State what counts as a working tool.** A working guardrail exits `0` only when `opa check` and every `opa test` case pass and `conftest test` agrees with them on the fixtures; exits `1` for policy violations on real input; exits `2` for an unreadable plan, a missing policy path, or a Rego parse error. The policy denies by message, never by silent evaluation error.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `is_object(rc.change.after_unknown)` guard before any lookup | Proves the rule cannot fail-open or crash when Terraform reports `after_unknown: null` |
| `actions in {"create","update"}` plus an explicit `["delete"]` skip | Proves the rule ignores teardown (where `after` is `null`) while still catching replacement (`["delete","create"]`) |
| `opa test -v` with positive, negative, unknown, and delete fixtures | Proves all four branches behave, which is the only way the unknown branch is ever exercised |
| `checkov --external-checks-dir <dir> --check <ID>` with `__init__.py` | Proves the custom check was discovered and run by ID, not silently skipped |
| `conftest test plan.json --policy policy/ --rego-version v1` | Proves the CI entry point parses v1 syntax with the same results as `opa test` |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```rego
package terraform.security
# BUG 1: Legacy OPA v0 syntax rejected by OPA 1.0+
# BUG 2: Misses 'update' actions, crashes on delete (after == null), and ignores after_unknown!
deny[msg] {
    rc := input.resource_changes[_]
    rc.type == "aws_s3_bucket_public_access_block"
    rc.change.after.block_public_acls == false
    msg := "bad acl"
}
```

**Production-Grade Starter Skeleton (USE):**

```rego
package terraform.s3_public_access_block

import rego.v1

applies_change(rc) if {
    is_array(rc.change.actions)
    some action in rc.change.actions
    action in {"create", "update"}
}

is_unknown(rc, field) if {
    au := object.get(rc.change, "after_unknown", {})
    is_object(au)
    object.get(au, field, false) == true
}

is_literal_true(rc, field) if {
    is_object(rc.change.after)
    rc.change.after[field] == true
    not is_unknown(rc, field)
}

deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_s3_bucket_public_access_block"
    applies_change(rc)
    not is_literal_true(rc, "block_public_acls")
    msg := sprintf("%s: block_public_acls must be literal true (actions=%v)", [rc.address, rc.change.actions])
}

test_deny_false_or_unknown if {
    count(deny) == 1 with input as {"resource_changes": [{"address": "aws_s3_bucket_public_access_block.b", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["update"], "after": {"block_public_acls": false}, "after_unknown": null}}]}
}

test_allow_literal_true_and_ignore_delete if {
    count(deny) == 0 with input as {"resource_changes": [
        {"address": "aws_s3_bucket_public_access_block.ok", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["create"], "after": {"block_public_acls": true}, "after_unknown": {}}},
        {"address": "aws_s3_bucket_public_access_block.del", "type": "aws_s3_bucket_public_access_block", "change": {"actions": ["delete"], "after": null, "after_unknown": {}}}
    ]}
}
```

**Why this matters:** `is_object(after_unknown)` runs before the lookup, so a `null` unknown map denies instead of erroring or passing, and the delete fixture proves teardown is excluded rather than accidentally reported.

## When It Is NOT This Issue

- **A policy denies a resource that is clearly compliant** — check whether the attribute is provider-computed; the plan simply does not contain the value, so the policy is reporting unknown as violation. Fix the tri-state test before adjusting the resource.
- **`conftest` rejects a valid `rego.v1` policy** — conftest versions before 0.57 shipped an older OPA; `--rego-version v1` exists as a flag and the default changed in later releases, so confirm both the flag and the bundled OPA version.
- **A Checkov custom check never appears in results** — the checks directory is missing `__init__.py`, so discovery skips the file. `--external-checks-dir` alone is not enough.
- **`opa test` passes but `conftest test` fails** — plan fixtures differ (a source manifest is not a plan); the policy is fine and the input shape is wrong.
- **Removing the blocking rule "fixes" a false positive** — the terminal evaluation rule is what enforces the threshold; exclusions belong on the specific detection target, not on the evaluation rule.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER write legacy OPA v0 `deny[msg] { ... }` rules without `import rego.v1` / `contains` / `if` — OPA 1.0+ rejects v0 syntax by default.
- NEVER check only `"create" in rc.change.actions` or call `object.get` on `after_unknown` without an `is_object` guard (null `after_unknown` fails open!); cover `create`, `update`, and `["delete","create"]`, and ignore pure `["delete"]`.
- NEVER ship Rego or Checkov (`BaseResourceCheck` / `CheckResult.FAILED`) policies without inline positive (deny) and negative (allow/delete) unit tests (`opa test -v`).
- NEVER claim a specific `scan_resource_conf` signature without checking the installed Checkov major — the `entity_type` parameter changed across major versions.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Input artifact type (plan vs source), Terraform `format_version`, and computed attributes for `iac-rego-opa-and-checkov-policy-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The policy, test, or check is specific and runnable (no generic 'encrypt everything' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: iac-rego-opa-and-checkov-policy-development
- **Target Stack & Schema**: Open Policy Agent Rego v1 (`import rego.v1`, `deny contains msg if`, `terraform show -json` with `create`/`update`/replacement + `is_object` `after_unknown` guard) + Checkov `BaseResourceCheck` Python custom policies
- **Safety, Scope & Exit-Code Guards**: [Read-only plan input, `paths:` scope filters, `--error` CI exit gate, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Unknown attributes, pure deletes, null `after`, conftest/OPA version skew]
- **Implementation**:
  [Runnable, self-contained Rego or Python check following the Starter Skeleton]
- **Self-Validation Command**: `opa check --strict policy.rego; opa test -v .`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`ci-cd-security-gate-and-sarif-tooling`](../ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Consumes these policy results as a PR gate
- [`sbom-cyclonedx-and-cve-reachability-tooling`](../sbom-cyclonedx-and-cve-reachability-tooling/SKILL.md) - The dependency-side counterpart to infrastructure guardrails
- [`custom-secret-scanner-detector-engineering`](../custom-secret-scanner-detector-engineering/SKILL.md) - Sibling pre-merge control with its own detector format
- [`cis-benchmark-and-baseline-compliance-scripting`](../cis-benchmark-and-baseline-compliance-scripting/SKILL.md) - Runtime host baselines that complement build-time policy
- [`purple-team-telemetry-validation-harnesses`](../purple-team-telemetry-validation-harnesses/SKILL.md) - Proves the deployed control still behaves as the policy intended

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `iac-rego-opa-and-checkov-policy-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1188`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 2 |
| Top sources | cyber-security/security-code (1), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
