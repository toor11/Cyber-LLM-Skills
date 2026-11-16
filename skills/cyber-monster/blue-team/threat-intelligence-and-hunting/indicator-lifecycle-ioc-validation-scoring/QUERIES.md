# Detection Queries and Telemetry Artifacts

> Sub-skill: [`indicator-lifecycle-ioc-validation-scoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Validation and scoring checks. Each row names the field and the state a defensible score shows.

## Provenance

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Primary source | `provenance.primary_source` with date | Present |
| Reseller detection | `reseller_chain` flag | Set where corroboration is illusory |
| Feed authentication | authenticated or signed feed | True for deployed indicators |

## Specificity

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Hosting context | shared versus dedicated infrastructure | Recorded for every network indicator |
| Actor control | registered or operated by the actor | Distinguishes owned from used space |
| Class | hash, domain, ipv4, url path, certificate | Recorded; drives the score cap |

## Prevalence and Action

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Estate prevalence | connections or matches in the last 30 days | Recorded including zero |
| Action | block / alert / hunt_with_context | Matches specificity; low specificity never blocks |
| Review date | `review` field | Before the class TTL expires |

## Telemetry Prerequisites

- Feed provenance metadata including upstream chain, which most aggregators discard.
- Traffic or telemetry prevalence data, since specificity alone understates collateral risk.
- A scoring worksheet, so two analysts reach similar numbers for the same indicator.

## Deployment Gates

- No block action on low-specificity infrastructure without a context condition.
- Corroboration counting excludes reseller chains; one upstream is one source.
