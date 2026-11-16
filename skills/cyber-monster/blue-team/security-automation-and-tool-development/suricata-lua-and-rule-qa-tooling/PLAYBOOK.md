# Operational Triage and Response Playbook

> Sub-skill: [`suricata-lua-and-rule-qa-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for an IDS rule-set incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- Sensor alert volume drops to zero after a rule deployment.
- `suricata -T` fails during a config or ruleset change.
- A `lua` rule stops firing after a Suricata upgrade.
- Throughput improves after a rule edit but coverage was expected to be unchanged.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Rule present in file, absent from load output | Unmet `requires` or load error | Run `suricata -T` with the production config and read the per-rule error |
| Alert count dropped after a `fast_pattern` move | Semantic change | Restore the previous pattern, re-run the PCAP pair, re-review as a detection change |
| Lua rule silent with no error entry | Sandbox termination | Bound loops and string growth; re-test under the installed Suricata version |
| Duplicate `sid` across files | Rule shadowing | Renumber the later rule, bump `rev`, re-run the differential |
| `stats.*` assertions failing on a healthy engine | Field rename | Update consumers to `stats.score` and add a stats assertion to CI |

## Containment and Recovery

1. **Preserve before mutating:** record the ruleset hash, `suricata --build-info`, the `suricata.yaml`, and the `eve.json` from both fixtures. A load failure without the config is not diagnosable.
2. **Check blast radius:** count affected sensors and confirm whether the rule set is shared; a shared set change alters every sensor at once.
3. **Eradicate the root cause:** correct the rule property or script bound, pass the load gate and the PCAP differential, then restore full alerting.
