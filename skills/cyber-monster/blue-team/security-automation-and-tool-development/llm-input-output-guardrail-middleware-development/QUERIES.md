# Detection Queries and Telemetry Artifacts

> Sub-skill: [`llm-input-output-guardrail-middleware-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Guardrail decision artifacts owned by this slug. Every refusal is logged; a refusal that is not logged is an invisible attack signal.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Refusal with `control: input_schema` | High | Arguments violated the tool's declared contract |
| 2 | Refusal with `control: tool_allowlist` | High | The model attempted an unreachable tool |
| 3 | Refusal with `control: egress_allowlist` | High | A call would have reached a non-permitted destination |
| 4 | Refusal with `control: canary_leak` | High | Untrusted-context content reached the output channel |
| 5 | Structured refusal visible to the agent | High | The agent can react instead of fabricating success |

## Detection Artifacts

```text
[llm-input-output-guardrail-middleware-development:rule-spec] authorize tool name, schema, scope, and destination before execution
[llm-input-output-guardrail-middleware-development:filter-fp] a jailbreak that never calls a tool is a prompt issue, not an authorization event
[llm-input-output-guardrail-middleware-development:correlate] request id ties the agent turn to the tool decision and the audit line
```

Validate arguments against a tool's published `inputSchema` before execution (Windows PowerShell 5.1 invoking Python):

```powershell
python -c "import json,jsonschema,sys; schema=json.load(open(sys.argv[1])); args=json.loads(sys.argv[2]); jsonschema.validate(args, schema); print('schema ok')" .\schemas\read_file.json '{\"path\":\"/srv/kb/index.json\"}'
if ($LASTEXITCODE -ne 0) { Write-Output "arguments rejected by inputSchema"; exit 1 }
```

Refusal-path fixtures that must each produce a distinct control name:

```text
[llm-input-output-guardrail-middleware-development:fixture] unknown tool name -> control=tool_allowlist
[llm-input-output-guardrail-middleware-development:fixture] wrong argument type -> control=input_schema
[llm-input-output-guardrail-middleware-development:fixture] path outside enum -> control=input_schema
[llm-input-output-guardrail-middleware-development:fixture] http destination not allowlisted -> control=egress_allowlist
[llm-input-output-guardrail-middleware-development:fixture] canary present in output -> control=canary_leak
```

Canary check applied to outbound text before it reaches the caller:

```python
def assert_no_canary(text: str, session_canary: str) -> None:
    if session_canary in text:
        raise RuntimeError("untrusted-context canary leaked into output")
    marker = "CANARY-"
    if marker in text:
        raise RuntimeError("a canary-shaped token appeared in output")

assert_no_canary("summary of three documents", "CANARY-0123456789abcdef")
print("canary check passed")
```

Audit-line shape, one per decision including refusals, with the offending span redacted:

```json
{"request_id": "3f2a9c11", "principal": "agent:kb-assistant", "tool": "read_file", "decision": "refuse", "control": "input_schema", "detail": "path is not one of the allowed values"}
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Alert on refusal rate per agent and per tool; a sudden change indicates either an attack or a broken tool contract.
- Load `inputSchema` from the tool definition at runtime so the middleware cannot drift from the contract it enforces.
