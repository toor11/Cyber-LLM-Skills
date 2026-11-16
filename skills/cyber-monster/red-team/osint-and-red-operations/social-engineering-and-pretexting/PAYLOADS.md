# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`social-engineering-and-pretexting`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `social-engineering-and-pretexting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Documented control baseline

Baseline: the written process step for identity verification. Probe: the observed handling during the pretext. Differential: a step present in the process and absent in behaviour is the finding.

```bash
python -c "import yaml; d=yaml.safe_load(open('se-scope.yaml')); print(d['baseline_control'])"
```

## Contact and debrief coverage

Baseline: contacts logged. Probe: contacts with a recorded debrief. Differential: an undebriefed contact is an open obligation, not a completed test.

```bash
sqlite3 se.db "SELECT COUNT(*) FROM contact;"
sqlite3 se.db "SELECT COUNT(*) FROM contact WHERE debriefed_at IS NULL;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
