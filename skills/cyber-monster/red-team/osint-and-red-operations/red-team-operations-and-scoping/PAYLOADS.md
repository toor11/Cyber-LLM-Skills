# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`red-team-operations-and-scoping`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `red-team-operations-and-scoping`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Scope membership check

Baseline: the enumerated in-scope list. Probe: the target of the next action. Differential: a target absent from the list stops the action.

```bash
python -c "import yaml, ipaddress; d=yaml.safe_load(open('scope.yaml')); n=ipaddress.ip_network('198.51.100.5/32'); print(any(n.subnet_of(ipaddress.ip_network(r)) for r in d['in_scope']['ranges']))"
python -c "import yaml; d=yaml.safe_load(open('scope.yaml')); print(d['in_scope']['hostnames'], d.get('excluded', {}).get('ranges'))"
```

## Window check

Baseline: the authorised window. Probe: the current time. Differential: an action outside the window is unauthorised regardless of scope.

```bash
python -c "import yaml, datetime; d=yaml.safe_load(open('scope.yaml')); print(d['window'], datetime.datetime.now(datetime.timezone.utc).isoformat())"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
