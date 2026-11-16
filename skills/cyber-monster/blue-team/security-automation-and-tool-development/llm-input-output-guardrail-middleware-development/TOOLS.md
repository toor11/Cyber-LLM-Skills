# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`llm-input-output-guardrail-middleware-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented parameters — check the installed package version if a signature differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11 with `jsonschema` (Draft 2020-12, the MCP `inputSchema` default), explicit tool and argument-value allowlists, per-session canary tokens, and outbound secret/PII/destination filters
- **Validation Gate:** `python -m py_compile guardrail.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `jsonschema` | `jsonschema.validate(instance, schema)` | Validate tool arguments against `inputSchema` | Python 3.11+ |
| `jsonschema` | `Draft202012Validator(schema).iter_errors(instance)` | Collect all violations instead of the first | Python |
| MCP | `tools/call` with `params.name` and `params.arguments` (JSON object) | The call shape the middleware authorizes | Protocol |
| MCP | `tools/list` returning each tool's `inputSchema` | Source of truth for the schema to enforce | Protocol |
| Python `re` | compiled canary pattern | Detect leakage of untrusted-context markers | Python 3.11+ |
| Python `uuid` | `uuid.uuid4().hex[:8]` | Per-request audit identifier | Python 3.11+ |
| Python `json` | `json.dumps(decision)` one line per decision | Append-only audit stream | Python 3.11+ |

## Minimal Script

```powershell
python -m py_compile .\guardrail.py
if ($LASTEXITCODE -ne 0) { Write-Output "module does not compile"; exit 2 }

python .\guardrail.py .\fixtures\permitted_call.json | Tee-Object -FilePath .\build\guardrail-audit.jsonl
$permit = $LASTEXITCODE

python .\guardrail.py .\fixtures\unknown_tool.json | Add-Content .\build\guardrail-audit.jsonl
$refuse = $LASTEXITCODE

Write-Output "permit=$permit refuse=$refuse"
if ($refuse -ne 1) { Write-Output "expected a policy refusal on the unknown-tool fixture"; exit 1 }
exit $permit
```

Exit-code contract: `0` permitted and fully validated, `1` refused by policy (with the control that fired), `2` configuration error such as an unloadable schema.
