# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`iac-rego-opa-and-checkov-policy-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative policy-as-code failures, each with the artifact that proves the diagnosis.

## Case 1: Guardrail passes an unencrypted volume

- **Surface & Preconditions:** a policy asserts `rc.change.after.encrypted == true` for a new volume.
- **Root cause & impact:** the provider computes `encrypted` at apply time, so the plan carries it under `after_unknown` and not in `after`. The comparison evaluates to undefined, the deny set stays empty, and the volume is created with whatever default the provider applies.
- **Verification & fix:** test `is_object(after_unknown)` then membership before reading `after`; treat unknown as deny for security-relevant attributes. Add a fixture whose `after` is empty and `after_unknown` marks the field, as in [`QUERIES.md`](QUERIES.md).

## Case 2: Policy crashes on every destroy-only change

- **Surface & Preconditions:** a policy dereferences `rc.change.after.ingress` for all `resource_changes`.
- **Root cause & impact:** a destroy sets `after: null`, so evaluation errors and the policy either fails the run or — worse, if the harness swallows errors — reports nothing. Either way the pipeline becomes unreliable during cleanup changes.
- **Verification & fix:** gate on `actions` first, exclude pure `["delete"]`, and add a delete fixture to `opa test` so the branch is permanently covered.

## Case 3: Custom Checkov check silently absent

- **Surface & Preconditions:** a `BaseResourceCheck` subclass is placed in a checks directory and run with `--external-checks-dir`.
- **Root cause & impact:** without an `__init__.py` the loader does not import the module, so the check never runs; `checkov` exits `0` and the team believes the policy is enforced.
- **Verification & fix:** assert the check ID appears in the run output (with `--check <ID>` it must be listed); keep the `__init__.py` in version control.

## Case 4: Same policy, two different verdicts

- **Surface & Preconditions:** `opa test` is green locally, `conftest test` fails in CI on the same policy file.
- **Root cause & impact:** the CI image bundles an older OPA (conftest before 0.57 shipped OPA 0.69-era binaries), so v1 syntax or a newer builtin behaves differently; or the fixture is a source manifest rather than a plan.
- **Verification & fix:** pin the conftest/OPA versions in the CI image, pass `--rego-version v1` explicitly, and assert on the plan fixture shape (`resource_changes`, not `resource`).
