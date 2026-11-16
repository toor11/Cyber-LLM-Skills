# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`python-ast-and-libcst-security-linters`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `python-ast-and-libcst-security-linters`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Fixture pair

Baseline: the negative fixture yields zero hits. Probe: the positive fixture yields exactly one. Differential: any extra hit is a rule defect.

```python
rule = Rule(open('fixtures/positive.py').read())
rule.visit(ast.parse(open('fixtures/positive.py').read()))
print(len(rule.hits))
```

## Tree dump for node shape discovery

Baseline: `ast.dump` of the target expression. Probe: `ast.dump` after the intended change. Differential: the node type you key on must appear in one and not the other.

```bash
python -m ast fixtures/positive.py
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
