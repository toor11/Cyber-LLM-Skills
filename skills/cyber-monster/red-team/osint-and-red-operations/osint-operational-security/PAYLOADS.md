# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`osint-operational-security`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `osint-operational-security`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Egress observation check

Baseline: the address the engagement intended a source to see. Probe: the address the source actually observed. Differential: a mismatch is an attribution risk to record and correct.

```bash
curl -sS https://ifconfig.example/
curl -sS -x http://egress.example:3128 https://ifconfig.example/
```

## Persona retirement coverage

Baseline: personas created. Probe: personas with a retirement record. Differential: an unretired persona is an open liability after the engagement.

```bash
python -c "import yaml; p=yaml.safe_load(open('opsec.yaml'))['personas']; print(len(p), sum(1 for x in p if not x.get('retired_at')))"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
