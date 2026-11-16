# Detection Queries and Telemetry Artifacts

> Sub-skill: [`threat-modeling-attack-tree-and-misuse-cases`](SKILL.md) | Family: **Application Security**

Tree-quality and coverage checks. Each row is answerable from the tree artefact and the control locations it cites.

## Structure

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Root type | root nodes in the tree document | A consequence, not a technique or a tool |
| Operator marking | AND/OR labels on internal nodes | Every internal node marked |
| Leaf testability | leaves carrying a request, condition, or config | All leaves; untestable nodes are expanded further |

## Break Points

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Located control | leaves or paths citing a file or config key | Every complete path has at least one |
| Missing break | paths with no located control | Each is a finding with an owner |
| Config condition | leaves depending on a production setting | Setting recorded and verified |

## Sequence Coverage

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Order sensitivity | misuse cases where step order matters | Each has a state-check control |
| Cumulative authority | sequences where each step is individually authorised | Aggregate limit or approval present |

## Telemetry Prerequisites

- A stated asset and harm for the root, agreed with the system owner.
- Repository access to locate the controls a path claims.
- The accepted-risk register for paths left open deliberately.

## Deployment Gates

- A tree with no located break point on any path is a brainstorm, not a model; send it back.
- Re-derive the tree when a control location changes, since the break points are the artefact's value.
