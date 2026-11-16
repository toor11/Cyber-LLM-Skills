# Operational Triage and Response Playbook

> Sub-skill: [`detection-engineering-behaviour-to-observable`](SKILL.md) | Family: **Detection and Monitoring**

Structured runbook for `detection-engineering-behaviour-to-observable`. Paired offensive/mechanics reference: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Triggers

- A behaviour is described in prose and nobody can say which event would record it.
- A rule exists for a technique and reads a field the deployed agent does not populate.
- A new platform enters the estate and the existing analytics have no equivalent observable there.
- A vendor model update changes an EDR verdict and the rules built on that verdict change behaviour without a code change.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Sampled event on the target build shows the discriminating field populated and the benign twin differs on it | Observable Confirmed | Author the rule against that field, and write the documented loss beside it |
| Event exists but the discriminating field is null for the relevant call origin | Control Gap (Field Population) | Choose another sensor or add a second event; do not author a rule on an unpopulated field |
| Event not emitted at all despite the config appearing to include it | Inconclusive (Collection Filter) | Dump the effective config, check forwarder filters, and re-sample; the sensor is not delivering what the schema documents |
| Benign twin indistinguishable on every emitted field | Control Gap (No Discriminating Attribute) | Move to a correlation of two events, or accept that this behaviour is not detectable with the current sensor set |
| Rule reads a vendor verdict label with no raw event behind it | Control Gap (Abstraction Coupling) | Document the coupling, request raw-event retention, and plan a raw-based analytic if the label changes |
| Two sensors carry the action with different losses | Benign Baseline (Design Choice) | Record which sensor was chosen and why; the alternative becomes the pivot in the rule documentation |
| Syscall or API observable absent because no audit rule selects it | Control Gap (Probe Absent) | Add the audit rule or an eBPF probe in the platform's change process, then re-sample |

## Containment and Recovery

1. **Preserve before mutating:** keep the sampled raw event, the config dump, and the benign counterpart; a translation reviewed without them cannot be re-derived after an agent upgrade.
2. **Change collection deliberately:** enabling a high-volume event on a production fleet to obtain an observable has a cost in storage and forwarder load; size it before the change and record the decision.
3. **Keep the alternative sensor documented:** the second-best observable becomes the pivot when the first one is lost to a vendor change, and that pivot belongs in the rule's notes rather than in someone's memory.
4. **Re-validate after agent or schema upgrades:** a translation is version-bound; add it to the upgrade checklist so a field rename is discovered by a test rather than by a missed detection.
