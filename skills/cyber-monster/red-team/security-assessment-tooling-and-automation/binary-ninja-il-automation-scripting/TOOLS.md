# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`binary-ninja-il-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `binaryninja` Python API, MLIL SSA form, HLIL for control-flow shape.
- **Validation Gate:** `python -c "import binaryninja; print(binaryninja.core_version())"` then one scripted run with `bv.update_analysis_and_wait()`.
- Scripts run headless with `binaryninja.headless` or through the GUI console; the API surface is the same, but headless has no UI log.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `binaryninja` | `python -c "import binaryninja; print(binaryninja.core_version())"` | Confirm the API version the script targets | Windows, Linux, macOS |
| `python` | `python -m py_compile classify_calls.py` | Catch syntax errors before a long analysis run | Cross-platform |
| `binaryninja headless` | `python classify_calls.py target.bin` | Run the classifier without the GUI | Windows, Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import binaryninja as bn

bv = bn.load("target.bin")
bv.update_analysis_and_wait()
rows = []
for func in bv.functions:
    ssa = func.mlil.ssa_form if func.mlil else None
    if ssa is None:
        continue
    for block in ssa.basic_blocks:
        for insn in block:
            if insn.operation == bn.MediumLevelILOperation.MLIL_CALL:
                rows.append((hex(insn.address), func.name, str(insn.dest)))
print(len(rows))
for r in rows[:20]:
    print(*r)
```
