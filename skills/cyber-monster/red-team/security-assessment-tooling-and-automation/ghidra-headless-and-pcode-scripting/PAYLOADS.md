# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ghidra-headless-and-pcode-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `ghidra-headless-and-pcode-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Call-target inventory baseline

Baseline: call inventory of the reference build. Probe: the same inventory for the shipped build. Differential: a new call target in shipped with no reference counterpart.

```python
from ghidra.app.decompiler import DecompInterface
ifc = DecompInterface()
ifc.openProgram(currentProgram)
print(len(list(currentProgram.getFunctionManager().getFunctions(True))))
```

## Function size baseline

Baseline: function entry and body size for a named function. Probe: the same after a patch. Differential: a body that grows without a corresponding new call indicates inserted logic.

```python
for f in currentProgram.getFunctionManager().getFunctions(True):
    print(hex(f.getEntryPoint().getOffset()), f.getBody().getNumAddresses())
```

## P-code call sites

Baseline: P-code calls per function. Probe: the same after the patch. Differential: a function whose call targets changed is the patch site.

```python
high = ifc.decompileFunction(f, 30, ConsoleTaskMonitor()).getHighFunction()
print([str(o.getInputs()[0]) for o in high.getPcodeOps() if o.getOpcode() == o.CALL])
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
