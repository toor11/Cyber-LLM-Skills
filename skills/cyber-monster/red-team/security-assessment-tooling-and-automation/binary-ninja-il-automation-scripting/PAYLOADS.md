# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`binary-ninja-il-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `binary-ninja-il-automation-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Call-site inventory baseline

Baseline: count MLIL call instructions per function. Probe: the same count restricted to indirect calls. Differential: only the restricted set is reviewed; a large unrestricted delta means the classifier is too broad.

```python
bv = binaryninja.load("target.bin"); bv.update_analysis_and_wait()
sum(1 for f in bv.functions if f.mlil for b in f.mlil.basic_blocks for i in b if i.operation == binaryninja.MediumLevelILOperation.MLIL_CALL)
```

## Def-use walk for a length argument

Baseline: the call site's argument expression. Probe: the SSA definitions behind it. Differential: a definition that originates from a read or a network call is the finding; one that originates from a constant is not.

```python
ssa = func.mlil.ssa_form
arg = ssa.get_instruction(call_addr).params[1]
print(arg, arg.var.definitions)
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
