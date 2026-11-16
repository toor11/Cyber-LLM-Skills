# Detection Queries and Telemetry Artifacts

> Sub-skill: [`security-awareness-and-training-program`](SKILL.md) | Family: **Purple Team and Program**

Programme-measurement checks. Each row names the metric and the state a measured programme shows.

## Behaviour Metrics

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Time to report | median minutes from delivery to report for genuine phishing | Tracked with the sample size |
| Voluntary reports | reports per 1,000 users per month | Tracked with the triage outcome |
| Process behaviour | out-of-band verification events from the ERP or helpdesk | Tracked |

## Method Discipline

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Comparability | simulation difficulty per period | Held constant, or the change is recorded |
| Measurement source | training platform versus real telemetry | Real signals carry the conclusion |
| Sample size | n per metric per period | Reported, since small samples mislead |

## Intervention

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Friction reduction | one-click reporting present | Yes |
| Feedback loop | reporters receive an outcome | Yes |
| Process enforcement | behaviours moved into system controls | Recorded where applicable |

## Telemetry Prerequisites

- Access to genuine report timestamps, which is the only real-world behaviour signal.
- A reporting channel that records submission times and outcomes.
- A commitment to hold simulation difficulty constant, or to record it when it changes.

## Deployment Gates

- No effectiveness claim rests on completion rate or click rate alone.
- Every metric reports its sample size and method; a metric without them is reported as indicative.
