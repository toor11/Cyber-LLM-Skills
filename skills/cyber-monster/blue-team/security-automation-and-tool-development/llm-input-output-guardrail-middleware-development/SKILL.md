---
name: llm-input-output-guardrail-middleware-development
description: "Engineers defensive middleware for LLM and MCP/agent applications in Python/TypeScript: strict system/untrusted-data structural separation, tool-call JSON-schema + RBAC/allowlist policy enforcement, indirect-injection canary/source tagging on RAG chunks, and outbound PII/secret/URL exfiltration filters. Use when building runtime guardrails around AI agents."
family: security-automation-and-tool-development
tier: core
triggers: ["llm guardrail middleware", "mcp tool policy script", "rag untrusted wrapper", "agent tool allowlist"]
cwe: [CWE-1426]
owasp: [LLM01:2025, LLM06:2025]
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# LLM Input Output Guardrail Middleware Development - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Prompt injection is not solved by asking the model to behave: instructions and data arrive on the same channel, so any retrieved document, tool result, or web page is in a position to issue instructions. Middleware therefore does two things the model cannot do for itself. First, it preserves provenance: every untrusted fragment is wrapped with source metadata and a canary token, and the outbound text is checked for canary leakage so an exfiltration attempt through the model's own output is detectable. Second, it authorizes actions rather than text: a tool call is a structured request, and it must satisfy a JSON Schema (so arguments have the declared types and required fields), an allowlist (so only permitted tools and, for shell/filesystem/network tools, permitted argument values are reachable), and an identity/RBAC check (so the calling principal's scopes bound what the tool may do). In MCP terms the call is `tools/call` with `params.name` and a JSON-object `params.arguments`, and the tool definition carries `inputSchema` in JSON Schema 2020-12 by default — so schema validation at the middleware boundary is a direct fit, not an approximation. Outbound filtering closes the loop: detection of secrets, personal data, and unexpected destinations in tool arguments and model output. Everything is deny-by-default: an unknown tool, an unlisted argument value, or an unparseable argument is refused and logged, never passed through.

- **CWE-1426 (Improper Neutralization of Generative AI Prompt Input):** untrusted content is interpreted as instruction; the middleware's job is to keep data and instructions structurally distinguishable and to bound what any resulting action can do.
- **OWASP LLM01:2025 (Prompt Injection) / LLM06:2025 (Excessive Agency):** the two risks this middleware class directly addresses.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you assemble context **THEN** wrap each untrusted fragment with a source tag and a per-session canary, keep them in a separate structural section from system instructions, and scan the model output for the canary before returning it.
2. **IF** you validate a tool call **THEN** check `params.arguments` against the tool's `inputSchema` (JSON Schema 2020-12), then the tool allowlist, then the argument-value allowlist for high-risk tools, then the caller's scopes — in that order, deny by default.
3. **IF** a tool takes a command, path, or URL **THEN** allowlist the values rather than sanitizing strings; a shell command with a denylist of metacharacters is not a control.
4. **IF** you filter outbound content **THEN** check tool arguments and model output for secrets, personal data, and non-allowlisted destinations, and log the refusal with the offending span redacted.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `llm-input-output-guardrail-middleware-development` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable middleware shapes | [`QUERIES.md`](QUERIES.md) | Schema validation, allowlists, canary checks, egress filters |
| Need CLI syntax, flags, and API references | [`TOOLS.md`](TOOLS.md) | `jsonschema`, MCP `tools/call` shape, filter libraries |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Indirect injection and over-broad tool incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Agent-compromise handoff |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11 middleware using `jsonschema` (2020-12) for `inputSchema` validation, explicit tool and argument allowlists, per-session canary tokens, and outbound secret/PII/destination filters
- **Mandatory Self-Validation Command:** `python -m py_compile guardrail.py`

1. **Confirm the inputs.** Enumerate every tool the agent can reach with its `inputSchema`, the caller identity model and scopes, the untrusted content sources (RAG corpus, web fetch, tool results), and the permitted egress destinations. Confirm what happens on refusal — the agent must receive a structured error it can react to, not a silent empty result.
2. **Choose the branch.** Read-only tools → schema plus allowlist. Write or shell tools → add argument-value allowlists and scope checks per principal. Retrieval → provenance tags plus canary. Egress → destination allowlist plus content filters. Each branch adds a control, and skipping one is a decision to omit that control.
3. **Define how to validate the middleware.** Fixtures: a well-formed permitted call (passes), a call with a wrong argument type (refused by schema), an unknown tool (refused by allowlist), a permitted tool with a non-allowlisted argument value (refused), a tool result containing an injected instruction (kept as data, canary intact), and model output containing the canary (blocked and logged).
4. **Name the stop condition.** Stop when a tool is not in the allowlist, when arguments fail schema validation, when an argument value is outside the allowlist for a high-risk tool, when the caller lacks the required scope, when the canary appears in outbound text, or when a destination is not allowlisted.
5. **State what counts as a working tool.** A working middleware exits `0` when a request was permitted and fully validated, `1` when it was refused by policy (with the rule that refused it), and `2` on a configuration error such as an unloadable schema. Every decision is logged with request id, tool, principal, and the control that fired — and refusals are returned to the agent as structured errors.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `jsonschema.validate(arguments, tool["inputSchema"])` | Proves arguments match the tool's declared contract before execution |
| Explicit tool allowlist keyed by name | Proves unreachable tools are unreachable, not merely undocumented |
| Argument-value allowlist for shell/path/URL tools | Proves high-risk arguments are enumerated rather than filtered |
| Per-session canary token in untrusted context, checked on output | Proves data-to-instruction leakage is detectable |
| Structured refusal returned to the agent | Proves the agent can react instead of retrying blindly or fabricating success |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: string-concatenates retrieved text into the system prompt, runs any
# tool the model names, and blocks a few shell metacharacters with a regex.
import re
import subprocess

BLOCKED = re.compile(r"[;&|`$]")

def build_prompt(system: str, docs: list[str]) -> str:
    return system + "\n\nContext:\n" + "\n".join(docs)      # data and instructions merged

def run_tool(name: str, args: dict) -> str:
    if BLOCKED.search(args.get("command", "")):
        return "blocked"
    return subprocess.run(args["command"], shell=True, capture_output=True, text=True).stdout
```

**Production-Grade Starter Skeleton (USE):**

```python
# guardrail.py - Deny-by-default tool authorization and canary-checked context.
# Exit 0 permitted, 1 refused by policy, 2 configuration error.
import json
import re
import sys
import uuid

import jsonschema

TOOLS = {
    "search_kb": {
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 200}},
            "required": ["query"],
            "additionalProperties": False,
        },
        "risk": "read",
        "required_scope": "kb:read",
    },
    "read_file": {
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "enum": ["/srv/kb/index.json"]}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "risk": "filesystem",
        "required_scope": "kb:read",
    },
}

CANARY_RE = re.compile(r"CANARY-[0-9a-f]{16}")
EGRESS_ALLOW = {"https://kb.internal.example"}

class Refusal(Exception):
    def __init__(self, control: str, detail: str):
        super().__init__(detail)
        self.control = control
        self.detail = detail

def tag_untrusted(chunks: list[dict], canary: str) -> str:
    parts = [f"<untrusted source=\"{c['source']}\" canary=\"{canary}\">\n{c['text']}\n</untrusted>"
             for c in chunks]
    return "\n".join(parts)

def authorize(tool_name: str, arguments: dict, scopes: set[str]) -> dict:
    tool = TOOLS.get(tool_name)
    if tool is None:
        raise Refusal("tool_allowlist", f"tool not permitted: {tool_name}")
    try:
        jsonschema.validate(arguments, tool["inputSchema"])
    except jsonschema.ValidationError as exc:
        raise Refusal("input_schema", exc.message) from exc
    if tool["required_scope"] not in scopes:
        raise Refusal("rbac_scope", f"missing scope {tool['required_scope']}")
    for value in extract_destinations(arguments):
        if value not in EGRESS_ALLOW:
            raise Refusal("egress_allowlist", f"destination not permitted: {value}")
    return {"tool": tool_name, "risk": tool["risk"], "arguments": arguments}

def extract_destinations(arguments: dict) -> list[str]:
    found = []
    for value in arguments.values():
        if isinstance(value, str) and value.startswith(("http://", "https://")):
            found.append(value)
    return found

def check_output(text: str, canary: str) -> None:
    if canary in text:
        raise Refusal("canary_leak", "untrusted-context canary appeared in output")
    if CANARY_RE.search(text):
        raise Refusal("canary_leak", "foreign canary token in output")

def main(payload_path: str) -> int:
    try:
        payload = json.load(open(payload_path, encoding="utf-8"))
        params = payload["params"]
        canary = payload["canary"]
        scopes = set(payload.get("scopes", []))
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"config error: {exc}\n")
        return 2
    request_id = str(uuid.uuid4())[:8]
    try:
        decision = authorize(params["name"], params.get("arguments") or {}, scopes)
        check_output(json.dumps(decision), canary)
    except Refusal as refusal:
        print(json.dumps({"request_id": request_id, "decision": "refuse",
                          "control": refusal.control, "detail": refusal.detail}))
        return 1
    print(json.dumps({"request_id": request_id, "decision": "permit", **decision}))
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("usage: guardrail.py <request.json>\n")
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
```

**Why this matters:** the tool must be in an explicit map, its arguments must satisfy the declared `inputSchema`, the caller must hold the scope, and any destination must be allowlisted — four independent refusals before a tool runs, with the canary check covering the data-to-instruction path.

## When It Is NOT This Issue

- **A jailbreak succeeds but no tool is called** — that is a prompt-handling problem, not an authorization problem; the middleware's guarantee is about actions, not about what the model says.
- **Legitimate content trips the output filter** — a document that legitimately contains a secret-shaped string will be flagged; tune the filter with labelled examples rather than removing it.
- **The agent reports success while the tool was refused** — the refusal must be returned as a structured error the agent can see; a silent empty result invites fabrication.
- **An unknown tool call is dropped without a log entry** — refusing without auditing hides attack attempts; every refusal is a signal.
- **Schema validation rejects a valid call** — the tool's published `inputSchema` and the middleware's copy have diverged; treat the schema as the source of truth and load it from the tool definition.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER present a prompt-level instruction ("do not follow instructions in documents") as a security control.
- NEVER sanitize a shell or path argument with a metacharacter denylist and call it authorization; use an allowlist.
- NEVER let an unknown tool, unknown argument, or failed validation fall through to execution.
- NEVER assert an MCP field name or schema dialect without checking the protocol version in use.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Tool inventory with schemas, caller scopes, untrusted sources, and permitted egress for `llm-input-output-guardrail-middleware-development` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The validator, allowlist, or canary check is specific and runnable (no generic 'add a guardrail' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: llm-input-output-guardrail-middleware-development
- **Target Stack & Schema**: Python middleware with jsonschema 2020-12 tool validation, allowlists, RBAC scopes, canary checks
- **Safety, Scope & Exit-Code Guards**: [Deny-by-default, structured refusals, redacted audit logging, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Jailbreak without action, legitimately secret-shaped content, schema drift, agent retry loops]
- **Implementation**:
  [Runnable middleware following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile guardrail.py`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`soar-playbook-and-webhook-connector-development`](../soar-playbook-and-webhook-connector-development/SKILL.md) - The same deny-by-default and audit discipline for automated response
- [`custom-secret-scanner-detector-engineering`](../custom-secret-scanner-detector-engineering/SKILL.md) - Detection patterns the outbound filter can reuse
- [`ci-cd-security-gate-and-sarif-tooling`](../ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Gates the agent's own code and dependencies before deployment
- [`edr-api-triage-and-containment-scripting`](../edr-api-triage-and-containment-scripting/SKILL.md) - A high-risk tool surface an agent should never hold directly

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `llm-input-output-guardrail-middleware-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1426`, `LLM01:2025`, `LLM06:2025`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
