# Operational Triage and Response Playbook

> Sub-skill: [`endpoint-detection-and-edr-operations`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `endpoint-detection-and-edr-operations`. Paired offensive/mechanics reference: [`edr-evasion-and-amsi-bypass`](../../../red-team/network-ad-and-endpoint/edr-evasion-and-amsi-bypass/SKILL.md).

## Triggers

- An endpoint alert names a lineage pair or a command line that a peer group does not share.
- A hunt hypothesis requires process-level evidence for a host and the EDR view is ambiguous.
- A host's agent stops checking in, or a policy rollback changes what the endpoint records.
- A volatile-state question needs memory evidence beyond what the agent recorded.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Rare lineage pair with matching command line, subsequent action events, and agreement from a second plane | Confirmed Malicious / Gap | Acquire volatile evidence, scope sibling hosts for the same lineage, then isolate with application-owner sign-off |
| Same lineage and command line present across the fleet with a stable peer count | Benign Baseline (Administration) | Record the management tool and the identity that runs it; exclude by the full lineage pair rather than by filename |
| Agent check-in stale across the whole window | Inconclusive (Sensor Gap) | Escalate as agent coverage; no endpoint negative is valid until the host reports again |
| Event category absent from the policy while the agent is healthy | Control Gap (Policy) | Request the policy change with the volume estimate, or pivot to Sysmon or the Windows channel for that category |
| Endpoint shows the connection but the flow record does not, or the reverse | Control Gap (Plane Disagreement) | Record which plane is blind and for which traffic class; the disagreement bounds every later conclusion |
| Live lineage differs from the reported lineage with impossible creation order | Confirmed Malicious (Suspected Tampering) | Treat as tampering, capture memory before containment, and correlate with Sysmon event 25 |
| Process identifier reused inside the window so the timeline mixes two processes | Inconclusive (Identifier Reuse) | Re-anchor on the creation timestamp and re-run; do not attribute the mixed timeline |

## Containment and Recovery

1. **Preserve before mutating:** capture memory, export the relevant event channels, and record the agent policy version; isolation terminates processes that the memory image would have described.
2. **Contain with the application owner's consent:** network isolation of a production cluster or a build server can halt a business function; confirm the blast radius and the rollback path before the action.
3. **Verify the containment held:** confirm the host is no longer communicating on the investigated destination and that the agent still reports, since an agent that stops reporting after isolation makes the verification impossible.
4. **Close the policy or coverage gap in the same record:** every finding that depended on a category the policy excluded becomes a configuration action with an owner, not a note in the ticket.
