# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`python-atheris-and-hypothesis-security-fuzzing`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `python-atheris-and-hypothesis-security-fuzzing`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Seeded property run

Baseline: the property with a fixed seed and the reference implementation. Probe: the same run against the target. Differential: a failure only in the target, with the minimised example.

```bash
pytest -q tests/test_props.py --hypothesis-seed=0
pytest -q tests/test_props.py -p no:randomly --hypothesis-show-statistics
```

## Atheris corpus replay

Baseline: the corpus directory replays clean. Probe: a discovered crash file. Differential: the crash file must raise the same exception on replay.

```bash
python -m fuzz_target -runs=0 corpus/
python -m fuzz_target corpus/crash-*
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
