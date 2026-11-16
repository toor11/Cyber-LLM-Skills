# Operational Triage and Response Playbook

> Sub-skill: [`llm-input-output-guardrail-middleware-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an agent-guardrail incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A tool call was refused repeatedly for one agent or one user.
- Output contained a canary or a secret-shaped string.
- An agent claimed an action that the tool log does not show.
- A newly added tool was reachable without an explicit allowlist entry.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Repeated `tool_allowlist` refusals | Probing or a broken prompt | Inspect the conversation; treat repeated unknown-tool calls as hostile |
| `canary_leak` refusal | Exfiltration attempt or filter bug | Block the session, review egress logs, verify the canary scope |
| `input_schema` refusals on a valid request | Schema drift | Reload `inputSchema` from the tool definition |
| Agent claims an action the tool log lacks | Fabricated success | Fix refusal signalling; treat the claim as false until proven |
| New tool reachable without an allowlist entry | Default-allow defect | Make the allowlist explicit and deny unknown names |

## Containment and Recovery

1. **Preserve before mutating:** keep the request id, the tool decision line, the agent turn transcript, and the tool-side log. The decision line is the only record of what the middleware permitted.
2. **Check blast radius:** enumerate other sessions using the same agent, tool set, and scopes, and check egress logs for the destinations that were attempted.
3. **Eradicate the root cause:** fix the allowlist, schema loading, or refusal signalling, replay the fixture set, and only then re-enable the agent for the affected principals.
