# Detection Queries and Telemetry Artifacts

> Sub-skill: [`secure-sdlc-and-security-requirements`](SKILL.md) | Family: **Application Security**

Programme-level checks over the requirement set and its gates. Each row is answerable from repository and pipeline metadata; a requirement that cannot answer its own row is not yet enforceable.

## Traceability

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Requirement to test | requirement ids referenced in test names, docstrings, or `@pytest.mark.security` | Every blocking requirement resolves to at least one test path |
| Requirement to standard clause | ASVS 5.0.0 id, SSDF practice id, or CIS Safeguard id in the requirement record | One clause per requirement; no clause cited by more than three requirements without a reason |
| Orphan requirement | requirement records with an empty owner field | Empty; each resolves to a team with an escalation path |

## Gate Liveness

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Deliberate-failure run | pipeline runs tagged `gate-probe` with a non-zero exit | At least one per blocking gate in the last 90 days |
| Gate bypass audit | merge commits with `skip-security` label or admin override | Zero unexplained overrides; each carries an accepted-risk id |
| Scanner currency | ruleset or database version recorded in the run artefact | Updated within the vendor's support window; stale rulesets are the usual cause of a gate that silently stopped matching |

## Adoption Evidence

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Exception inventory | accepted-risk records with expiry and compensating control | No expired exception still suppressing a finding |
| Trend | findings per release by severity | Falling or flat while scope grows; a rising trend means the requirement is not being met at authoring time |

## Telemetry Prerequisites

- Read access to pipeline history, not just the current configuration, because gate liveness is a property of runs.
- The requirement register with owners, so traceability can be measured rather than asserted.
- A mapping from requirement ids to the standard clauses the organisation has committed to.

## Deployment Gates

- No blocking requirement ships without a recorded deliberate-failure run; treat it as a release blocker, since an unproven gate is worse than none.
- Expired exceptions must fail the pipeline rather than linger in a spreadsheet.
