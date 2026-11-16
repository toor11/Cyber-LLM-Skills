# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ctf-and-lab-methodology`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `ctf-and-lab-methodology`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Artefact identification

Baseline: the file hash at acquisition. Probe: the format and architecture. Differential: a format that does not match the challenge category means the category was misread.

```bash
sha256sum challenge.bin
file challenge.bin
```

## Attempt log entry

Baseline: the hypothesis and its expected observation. Probe: the actual output. Differential: a mismatch closes the hypothesis rather than extending it.

```bash
date -u +%H:%M:%S
./challenge < /dev/null; echo "exit=$?"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
