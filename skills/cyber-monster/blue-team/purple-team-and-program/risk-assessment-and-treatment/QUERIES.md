# Detection Queries and Telemetry Artifacts

> Sub-skill: [`risk-assessment-and-treatment`](SKILL.md) | Family: **Purple Team and Program**

Register-quality checks. Each row names the field and the state a usable register shows.

## Scenario Quality

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Cause-event-consequence | scenario field | All three parts present |
| Asset and entity | scope field | Named, so impact can be priced |
| Duplication | scenarios sharing a consequence | Merged or cross-referenced |

## Scoring

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Anchors | scale definition table | Published and referenced by every entry |
| Residual basis | controls considered per entry | Named |
| Comparability | score distribution across entries | Plausible spread, not all critical |

## Treatment

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Treatment type | mitigate / transfer / avoid / accept | One per entry |
| Owner and expiry | assignee and review date | Present |
| Re-score trigger | event that triggers reassessment | Defined |

## Telemetry Prerequisites

- Impact anchors denominated in something the organisation already measures (money, customers, downtime).
- A control inventory, since residual scoring depends on what exists.
- A review forum that can accept risk, because acceptance requires authority.

## Deployment Gates

- No entry carries a score without the anchor table that produced it.
- Accepted risks always carry an expiry; the entry reappears when it passes.
