# Detection Queries and Telemetry Artifacts

> Sub-skill: [`iac-rego-opa-and-checkov-policy-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Policy, plan-fixture, and test artifacts owned by this slug. Confirm `format_version` on your plan fixtures against the Terraform version producing them before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `after_unknown[field] == true` while `after[field]` is absent | High | The value is provider-computed; a policy reading only `after` cannot judge it |
| 2 | `change.actions` == `["delete"]` with `after: null` | High | Teardown, not a violation; dereferencing `after` here is a policy bug |
| 3 | `opa test` case count per rule branch | High | Every branch (fail, pass, unknown, delete) is exercised, not just the happy path |
| 4 | `conftest test --rego-version v1` exit status | High | The CI entry point parses v1 syntax with the same conclusions as `opa test` |
| 5 | Checkov check absent from `--check <ID>` output | High | The custom check was never discovered (usually a missing `__init__.py`) |

## Detection Artifacts

```text
[iac-rego-opa-and-checkov-policy-development:rule-spec] deny set populated only for actions in {create, update} and non-literal-true attributes
[iac-rego-opa-and-checkov-policy-development:filter-fp] policy passes a resource whose attribute is present in after_unknown -> fail-open defect
[iac-rego-opa-and-checkov-policy-development:correlate] each deny message carries rc.address and rc.change.actions for attribution
```

Policy gate in CI (Windows PowerShell 5.1):

```powershell
opa check --strict .\policy\terraform.rego
if ($LASTEXITCODE -ne 0) { Write-Output "rego parse/lint failed"; exit 2 }
opa test -v .\policy\
if ($LASTEXITCODE -ne 0) { Write-Output "policy tests failed"; exit 1 }
conftest test .\fixtures\plan.json --policy .\policy\ --rego-version v1
```

Producing the plan JSON that the policy consumes:

```powershell
terraform init -input=false | Out-Null
terraform plan -out .\build\tfplan.binary | Out-Null
terraform show -json .\build\tfplan.binary | Set-Content .\build\tfplan.json
```

Minimal plan fixture that exercises the unknown branch (the case most policies never test):

```json
{
  "format_version": "1.2",
  "resource_changes": [
    {
      "address": "aws_s3_bucket_public_access_block.example",
      "type": "aws_s3_bucket_public_access_block",
      "change": {
        "actions": ["create"],
        "after": {},
        "after_unknown": {"block_public_acls": true, "block_public_policy": true}
      }
    }
  ]
}
```

Custom Checkov check discovery:

```powershell
checkov --external-checks-dir .\custom_policy --check CKV_AWS_999 --framework terraform -d .\infra
if ($LASTEXITCODE -ne 0) { Write-Output "policy violation or discovery failure" }
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Require one `test_` case per branch before a policy rule can merge; an untested unknown branch is a fail-open waiting to happen.
- Pin the OPA version used by `conftest` so policy results do not change under a tool upgrade.
