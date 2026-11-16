# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`angr-and-z3-constraint-solver-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `angr-and-z3-constraint-solver-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Baseline then probe: stdin validators

Baseline: a well-formed input of the expected length, run to completion. Probe: the same harness with the buffer symbolic. Differential: the success address is reached in the probe and never in the baseline.

```python
state = proj.factory.entry_state(stdin=angr.SimFileStream)
simgr.explore(find=SUCCESS_ADDR, avoid=ERROR_ADDR, num_find=1)
found.solver.eval(found.posix.stdin.load(0, found.posix.stdin.size), cast_to=bytes)
```

## Standalone arithmetic model

Baseline: the concrete index the harness passes. Probe: the same index symbolic. Differential: only a sat model that the harness then accepts counts.

```python
idx = z3.BitVec("idx", 32)
s = z3.Solver()
s.add(z3.ULT(idx, z3.BitVecVal(16, 32)), idx == 0xDEAD)
print(s.check(), s.model())
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
