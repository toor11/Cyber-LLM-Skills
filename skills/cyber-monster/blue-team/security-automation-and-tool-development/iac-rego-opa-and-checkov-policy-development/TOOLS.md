# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`iac-rego-opa-and-checkov-policy-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `<tool> --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Open Policy Agent Rego v1 (`import rego.v1`, `deny contains msg if`, `opa test`) driven through `conftest`, plus Checkov custom checks extending `BaseResourceCheck`
- **Validation Gate:** `opa check --strict policy.rego; opa test -v .`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `opa` | `opa check --strict policy.rego` | Parse and lint a Rego v1 policy | Cross-platform |
| `opa` | `opa test -v .` | Run `test_` rules with verbose per-case output | Cross-platform |
| `opa` | `opa eval -f pretty -i plan.json 'object.keys(input)'` | Inspect the plan document before writing rules | Cross-platform |
| `conftest` | `conftest test plan.json --policy policy/ --rego-version v1` | Evaluate policies against a plan in CI shape | Cross-platform |
| `terraform` | `terraform show -json tfplan.binary > tfplan.json` | Serialize a saved plan, including `after_unknown` | Cross-platform |
| `checkov` | `checkov --external-checks-dir ./custom_policy --check CKV_AWS_999 -d ./infra` | Load and run a custom check by ID | Cross-platform |
| `checkov` | `checkov -o sarif --output-file-path ./results.sarif` | Emit machine-readable findings for a CI gate | Cross-platform |
| `checkov` (Python) | `BaseResourceCheck` subclass with `name`, `id`, `supported_resources`, `categories`, `scan_resource_conf` | Custom policy for source config or unsupported frameworks | Python |

## Minimal Script

```powershell
opa check --strict .\policy\terraform.rego
$lint = $LASTEXITCODE
if ($lint -ne 0) { Write-Output "rego lint failed: $lint"; exit 2 }

opa test -v .\policy\
$unit = $LASTEXITCODE
if ($unit -ne 0) { Write-Output "policy unit tests failed: $unit"; exit 1 }

conftest test .\build\tfplan.json --policy .\policy\ --rego-version v1
$ci = $LASTEXITCODE
Write-Output "conftest exit=$ci"
```

Exit-code contract: `0` lint clean, unit tests green, and no violations on compliant input; `1` a test or policy violation; `2` unreadable plan, missing policy path, or Rego parse error.
