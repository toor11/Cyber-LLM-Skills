# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`semgrep-rule-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `semgrep-rule-engineering`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Fixture pair gate

Baseline: the `# ok:` fixture must yield zero findings. Probe: the `# ruleid:` fixture must yield exactly one. Differential: any other count fails the test.

```bash
semgrep --validate --config rule.yaml
semgrep --test rule.yaml
```

## Scoped scan with JSON output

Baseline: findings on the pre-fix commit. Probe: findings on the fix commit. Differential: the specific finding must disappear while unrelated rule hits stay constant.

```bash
semgrep --config rule.yaml --json --output=out.json src/
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
