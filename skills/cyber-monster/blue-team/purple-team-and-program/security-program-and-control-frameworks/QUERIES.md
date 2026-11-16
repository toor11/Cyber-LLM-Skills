# Detection Queries and Telemetry Artifacts

> Sub-skill: [`security-program-and-control-frameworks`](SKILL.md) | Family: **Purple Team and Program**

Programme-structure checks. Each row names the artefact and the state a maintained programme shows.

## Versions and Profile

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Framework version | versions recorded per framework | Pinned and reviewed |
| Profile currency | `current_scored` and `next_review` | Within the review cycle |
| Target profile | target outcomes selected and prioritised | Present, distinct from current |

## Mapping

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Clause coverage | applicable clauses with a control id | 100%, or an accepted gap |
| Control justification | frameworks and risks per control | At least one |
| Owner | controls without an owner | Zero |

## Testability

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Test method | method and frequency per control | Defined |
| Last test | date and result per control | Inside the frequency |
| Evidence path | evidence stored per test | Present |

## Telemetry Prerequisites

- The obligations list, since frameworks are only a vocabulary over it.
- A control register with owners, because an unowned control cannot be tested or defended.
- A profile mechanism (NIST provides a spreadsheet template) that is actually re-scored.

## Deployment Gates

- No control is reported implemented without a test method and a last-test date.
- Framework versions are reviewed annually, because benchmark and control revisions change mappings.
