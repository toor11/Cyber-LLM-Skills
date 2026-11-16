# Detection Queries and Telemetry Artifacts

> Sub-skill: [`sector-threat-landscape-analysis`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Landscape-product checks. Each row names the field and the state a defensible product shows.

## Cohort

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Definition | sub-sector, size band, geography, technology | All four stated |
| Denominator | organisation count in the cohort | Present for every prevalence claim |
| Comparability | same method as the baseline period | Yes, or the change is labelled a method change |

## Bias

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Source class | disclosure, ISAC, vendor, regulator, internal | Labelled per input |
| Bias note | how each source class distorts the claim | Present per claim |
| Excluded claims | claims removed as artefacts, with the reason | Recorded, not silently dropped |

## Action

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Priority shift | what the analysis changes | Stated explicitly |
| Confidence | level with basis | Present |

## Telemetry Prerequisites

- A cohort definition agreed with the consumer, since prevalence depends entirely on it.
- ISAC or peer reporting access, because internal data alone cannot describe a sector.
- A baseline period under the same method, or the change claims are uninterpretable.

## Deployment Gates

- No prevalence claim without a denominator and a bias note.
- Claims traceable to a reporting-threshold change are excluded from prevalence and reported separately.
