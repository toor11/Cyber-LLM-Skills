# Operational Triage and Response Playbook

> Sub-skill: [`volatility3-plugin-and-memory-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Structured runbook for a memory-triage incident. Paired offensive/mechanics reference: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).

## Triggers

- A triage report shows no anomalies on a host believed compromised.
- A plugin fails with a requirement or symbol error mid-run.
- `malfind` output is dominated by known JIT-heavy processes.
- Two runs on the same image produce different row counts.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| All plugins return zero rows | Symbol resolution failure | Verify the ISF bundle against the image build; do not report a verdict |
| `psscan` PIDs absent from `pslist` | Unlinked processes | Corroborate with create times and parent PIDs; escalate if the process is live |
| Many RWX regions in browser/.NET processes | Expected JIT behaviour | Corroborate with `vadinfo` module backing before escalating |
| Requirement exception in one plugin | Declared dependency unsatisfied | Fix the version requirement; never strip it to make the run pass |
| Non-deterministic row counts | Non-reproducible run | Re-hash the image and re-run with a pinned Volatility version |

## Containment and Recovery

1. **Preserve before mutating:** hash the memory image, record the Volatility version, the symbol path, and every plugin's row count. The image is the only copy of that state.
2. **Check blast radius:** determine whether the triage gap affects one host or every host processed by the same wrapper; a symbol-bundle defect silently poisons an entire case load.
3. **Eradicate the root cause:** fix symbol provisioning or the requirement declaration, re-run the full plugin set, and re-issue the report with the corrected row counts attached.
