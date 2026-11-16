# Operational Triage and Response Playbook

> Sub-skill: [`threat-modeling`](SKILL.md) | Family: **Application Security**

Structured runbook for `threat-modeling`. Paired offensive/mechanics reference: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `threat modeling`.
- Alert, hunt outlier, or review request matching `stride`.
- Alert, hunt outlier, or review request matching `attack tree`.
- Alert, hunt outlier, or review request matching `design review threat`.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Boundary crossing has no located control | Control gap | Add the control or an accepted-risk entry with owner and review date |
| Model contradicts running config | Model drift | Reconcile toward the config; the config is the thing attackers meet |
| Threat requires an out-of-scope actor | Out of scope | Hand to the model that owns that actor and record the handoff |

## Containment and Recovery

1. **Freeze the model to a version** and cite the commit or document revision in the review so a later reader can tell which design was assessed.
2. **Convert high-severity threats into replayable probes** and hand them to the team that owns the control, so the model expires into tests rather than into a wiki.
3. **Re-run reconciliation after the change lands**, not at the next planning cycle; drift is the only failure mode that makes a correct model dangerous.
