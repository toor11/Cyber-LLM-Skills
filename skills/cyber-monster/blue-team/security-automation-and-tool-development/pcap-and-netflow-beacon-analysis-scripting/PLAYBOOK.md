# Operational Triage and Response Playbook

> Sub-skill: [`pcap-and-netflow-beacon-analysis-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a suspected-beacon incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A flow shows low-variance periodicity to an unfamiliar destination.
- DNS volume to one parent domain spikes with long random labels.
- An IDS or Zeek notice names a periodic connection.
- A hunt produces a candidate list dominated by known infrastructure.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| Low CV plus consistent JA3 and uniform payloads | Strong beacon candidate | Pivot on destination across proxy/DNS logs; check host for the matching process |
| Low CV on a known patch or NTP destination | Benign periodicity | Add to the baseline list; do not chase |
| Long labels with high NXDOMAIN ratio | Tunneling or DGA | Extract parent domains, check resolver logs, block at DNS with care |
| Candidate count high across many flows | Threshold or sample floor wrong | Re-baseline benign traffic before tuning thresholds |
| Flow table truncated during analysis | Incomplete evidence | Re-run with a larger bound or split the capture by time |

## Containment and Recovery

1. **Preserve before mutating:** hash and retain the capture, record the analyzer version, the flow key granularity, and the statistics for each candidate; the raw capture is the only re-analysable evidence.
2. **Check blast radius:** pivot the destination and JA3 across all hosts before assuming a single infected endpoint.
3. **Eradicate the root cause:** block or contain the confirmed infrastructure, then add the benign periodic flows to the baseline so the next hunt is not spent re-litigating them.
