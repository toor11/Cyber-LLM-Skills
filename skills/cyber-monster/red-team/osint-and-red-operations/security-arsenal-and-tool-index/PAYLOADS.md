# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`security-arsenal-and-tool-index`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `security-arsenal-and-tool-index`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Entry runnability check

Baseline: the index entry's invocation. Probe: running it against a lab target. Differential: an invocation that fails means the entry is stale and the version or flags changed.

```bash
python -c "import yaml; e=yaml.safe_load(open('index.yaml'))['entries'][0]; print(e['invocation'])"
python -c "import yaml; [print(e['tool'], e['version'], e['format']) for e in yaml.safe_load(open('index.yaml'))['entries']]"
```

## Output format confirmation

Baseline: the declared format. Probe: the actual output's first bytes. Differential: a mismatch breaks downstream parsing silently.

```bash
nmap -sV -Pn -p 443 -oX - 127.0.0.1 | head -3
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
