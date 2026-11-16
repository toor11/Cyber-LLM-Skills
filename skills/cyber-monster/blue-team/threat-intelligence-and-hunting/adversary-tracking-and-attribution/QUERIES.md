# Detection Queries and Telemetry Artifacts

> Sub-skill: [`adversary-tracking-and-attribution`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Attribution-record checks. Each row names the field and the state a defensible judgement shows.

## Signals

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Prevalence | base rate per signal in the corpus or ecosystem | Recorded; low-prevalence signals carry the judgement |
| Independence | signals that do not derive from the same artefact | At least two independent signals |
| Vertex coverage | infrastructure, capability, victimology, operational | At least three vertices before a cluster claim |

## Reasoning

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Alternatives | competing hypotheses with what each explains | Present |
| Falsifier | what would change the assessment | Stated |
| Confidence basis | why the level was chosen | Recorded |

## Use

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Decision | the decision the attribution informs | Named; otherwise no naming |
| Audience | classification and distribution list | Present |

## Telemetry Prerequisites

- A corpus with prevalence data, since discrimination cannot be judged without base rates.
- Infrastructure registration or certificate data for the cluster under review.
- A review path for external claims, because a published attribution carries legal exposure.

## Deployment Gates

- No actor name is published on a single signal or without an alternative hypothesis considered.
- Every attribution product names the decision it informs.
