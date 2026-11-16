# Operational Triage and Response Playbook

> Sub-skill: [`windows-artifact-forensics-registry-artifacts`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `windows-artifact-forensics-registry-artifacts`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `registry forensics`.
- Alert, hunt outlier, or review request matching `ntuser.dat analysis`.
- Alert, hunt outlier, or review request matching `registry persistence`.
- A Sysmon 12/13/14 registry write alert needs validation against the hive state.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Autostart value written inside the incident window, absent from the peer-host baseline, with a matching Sysmon 12/13 or Security 4657 record | Confirmed Persistence | Preserve hive plus `.LOG1`/`.LOG2` and the event; export the referenced binary before cleanup |
| Autostart value identical on every host of the same build, with no incident-window `LastWrite` | Benign Baseline | Record the value set as the image baseline for that build; suppress by value rather than by key |
| Hive parsed without `.LOG1`/`.LOG2` and no persistence value found | Inconclusive (Stale Hive) | Re-collect the logs and re-parse before reporting; the newest value may exist only in the logs |
| `Services` key with an unusual `ImagePath` but no 7045 and no `Start`/`Stop` record | Configured But Not Executed | Report configuration only; pivot to Prefetch or SRUM for execution |
| `UserAssist` entry with a non-zero run count and a last-execution time inside the window | Interaction Confirmed | Treat as user-launched GUI activity; corroborate with Prefetch before attributing intent |

## Containment and Recovery

1. **Preserve before mutating:** collect each hive together with its `.LOG1`/`.LOG2` and hash both, because the logs may hold the only copy of the newest persistence value.
2. **Capture the control-set state:** record `Select\Current` and the OS build so a later reviewer can reproduce which `ControlSet00N` the finding came from.
3. **Rebuild baselines deliberately:** after any authorised software rollout, refresh the fleet baseline file, otherwise every newly deployed legitimate autostart value becomes a false positive on the next hunt.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
