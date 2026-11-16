# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`lab-and-tooling-setup`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `lab-and-tooling-setup`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Isolation verification

Baseline: the corporate range that must be unreachable. Probe: a route lookup and a connection attempt from the lab. Differential: both must fail; a success means the lab is misconfigured.

```bash
ip route get 10.20.0.5
curl -sS --max-time 3 -o /dev/null -w '%{http_code}\n' http://10.20.0.5/ || echo 'unreachable'
```

## Tool manifest check

Baseline: the pinned versions. Probe: the installed versions. Differential: a mismatch explains result differences between analysts.

```bash
python -c "import yaml; print(yaml.safe_load(open('lab.yaml'))['tools'])"
nmap --version | head -1
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
