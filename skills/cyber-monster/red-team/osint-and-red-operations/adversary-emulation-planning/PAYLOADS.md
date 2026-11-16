# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`adversary-emulation-planning`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `adversary-emulation-planning`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Coverage verdict tally

Baseline: steps with an expected detection. Probe: steps whose detection fired. Differential: an unfired expected detection is a coverage gap, an unexpected alert is a false negative in the plan.

```bash
sqlite3 emulation.db "SELECT technique, expected_detection, fired FROM steps;"
sqlite3 emulation.db "SELECT COUNT(*) FILTER (WHERE fired=1), COUNT(*) FROM steps;"
```

## Telemetry presence check

Baseline: the telemetry sources claimed in scope. Probe: a query proving each source produces events. Differential: a claimed source with no events cannot support any detection verdict.

```bash
sqlite3 emulation.db "SELECT source, COUNT(*) FROM telemetry_sample GROUP BY source;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
