# Detection Queries and Telemetry Artifacts

> Sub-skill: [`diamond-model-and-campaign-clustering`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Cluster-quality checks. Each row names the field and the state a defensible cluster shows.

## Vertices

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Coverage | all four vertices populated per incident | Present, including unknown adversary |
| Confidence per entry | confidence field per vertex item | Recorded |
| Source | source per entry | Recorded, so prevalence can be checked |

## Edges

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Edge type | capability, infrastructure, victim, adversary | Recorded per link |
| Prevalence | base rate of the edge in the corpus | Low-prevalence edges carry the claim |
| Independence | edges that do not derive from one artefact | At least two strong edges |

## Reasoning

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Competing hypotheses | ACH table with what each explains | Present |
| Verdict and confidence | cluster verdict with its basis | Present |

## Telemetry Prerequisites

- A corpus with prevalence data, since edge strength is meaningless without base rates.
- Incident records with at least capability and infrastructure detail.
- A place to record hypotheses, because the reasoning is the deliverable.

## Deployment Gates

- No campaign claim on a single edge or on high-prevalence edges alone.
- Every cluster records at least one competing hypothesis and what it fails to explain.
