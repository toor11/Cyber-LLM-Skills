# Detection Queries and Telemetry Artifacts

> Sub-skill: [`ai-and-llm-application-defense`](SKILL.md) | Family: **Application Security**

Telemetry-based checks for LLM features. Each row names the field the platform can emit and the pattern that indicates the control failed.

## Capability Scope

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Tool inventory vs caller scope | tool-call log with `tool.name`, `caller.id`, `credential.scope` | Every call's credential scope is a subset of the caller's entitlements |
| Approval bypass | calls to tools marked `requires_approval` with no approval event | Zero |
| Egress from tool runtime | `network.destination` on tool-runtime connections | Only allowlisted hosts, no raw IPs, no link-preview fetches |

## Context Integrity

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Cross-tenant retrieval | `retrieval.tenant_id` versus `request.tenant_id` | Always equal; a mismatch is a disclosure incident |
| Injection marker in retrieved text | retrieved chunk containing imperative patterns or hidden text (`display:none`, zero-width characters) | Flagged and excluded from context |
| Memory write from untrusted turn | `memory.write` events whose source is user or retrieved content | Restricted to verified sources |

## Output Handling

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Sink class | `output.render_mode` for generated content | Encoded text or sandboxed preview; never raw HTML or executed code |
| Schema validation failure | structured-output parse errors | Rejected and retried, not passed through |
| Cost and volume | `usage.total_tokens` and request rate per tenant | Inside the per-tenant budget; bursts alerted |

## Telemetry Prerequisites

- Structured logging of tool calls with the caller identity and the credential scope used, which is the only way to prove least privilege after the fact.
- A staging corpus containing an injected document, so the probe is reproducible.
- The vector store's metadata schema, to confirm tenant filtering happens server-side.

## Deployment Gates

- No tool ships with credentials broader than the narrowest caller that can trigger it.
- The injection probe runs in CI against the staging corpus; a change in tool-call shape fails the build.
