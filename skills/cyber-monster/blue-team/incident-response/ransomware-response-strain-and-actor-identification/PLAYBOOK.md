# Operational Triage and Response Playbook

> Sub-skill: [`ransomware-response-strain-and-actor-identification`](SKILL.md) | Family: **Incident Response**

Structured runbook for `ransomware-response-strain-and-actor-identification`. Paired offensive/mechanics reference: [`enterprise-appliance-and-n-day-exploitation`](../../../red-team/web-and-application/enterprise-appliance-and-n-day-exploitation/SKILL.md).

Victim-side artifact characterisation only. No actor contact, no group attribution from technical artifacts, no negotiation content.

## Triggers

- A note, an unfamiliar extension or a dropped binary appears and the report needs to say what family it is compatible with.
- An insurer, regulator or law-enforcement contact asks for a family-level description as part of a notification.
- Containment needs to anticipate the next stage and the family's documented behaviour would change what you contain first.
- Two host groups look different and the question is whether that is one deployment or two.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Note plus extension plus a preserved binary hash, all consistent | Identification Supported | State the family-compatible conclusion with its evidence and move to containment breadth |
| Note structure plus extension agree, no binary | Identification Probable | Report as probable; say a binary would raise it to supported |
| Extension only, no note and no binary | Hypothesis Only | Do not name a family in external communications; continue artifact preservation |
| Note exists but no encryption and no access change | Unconfirmed Claim | Treat as hoax or leftover; preserve the file, do not invoke recovery |
| Two distinct note structures across host groups | Two Deployments Suspected | Scope and contain separately; a second operator changes the whole response |
| Documented exfiltration-first behaviour matches, and an off-list transfer exists | Confirmed Plus Exfiltration Indicator | Route to `raas-extortion-and-negotiation-triage` immediately |
| Sample destroyed by cleanup before preservation | Inconclusive - Artifact Destroyed | Record the loss; use notes and telemetry only and state the confidence ceiling |

## Containment and Recovery

1. **Preserve before you describe.** Hash the note and a sample, copy them off-host, and only then analyse. A family name derived from a file that no longer exists cannot be defended or revised.
2. **Let the family change the order, not the scope.** A documented persistence shape tells you what to look for first on every host; it never narrows the host list. Scope comes from evidence, family informs sequence.
3. **Publish attribution at the confidence the artifacts support.** "Compatible with" is a defensible claim; "is" is not, unless two artifact classes plus a confirmed behaviour support it. Say which of those you have.
4. **Treat the exfiltration question as independent.** A family's reputation for double extortion is a reason to look hard at egress, not a finding. The finding is a completed transfer record; until then the answer is unproven, and counsel should be told it is unproven.
5. **Hand the confidence ceiling to the next skill.** Containment and recovery need to know whether the family is established or hypothesised, because a hypothesis must not be used to justify a narrowed scope in either direction.
