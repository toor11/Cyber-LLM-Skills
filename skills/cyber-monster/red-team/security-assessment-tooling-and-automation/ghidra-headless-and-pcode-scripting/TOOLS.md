# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ghidra-headless-and-pcode-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Ghidra 12.x, `DecompInterface` with `getHighFunction()`, PyGhidra 3.x (`pyghidra.analyze`) for Python-driven runs.
- **Validation Gate:** `analyzeHeadless` exit status plus one scripted run whose output names an address a reviewer can open.
- Ghidra 12.1.4 changed headless behaviour so it no longer writes to the user's preferences; scripts that relied on persisted preferences must pass options explicitly.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `analyzeHeadless` | `analyzeHeadless /tmp/proj audit -import target.bin -postScript Audit.py` | Reproducible import, analysis, and scripted post-processing | Windows, Linux, macOS |
| `pyghidra` | `python -c "import pyghidra; pyghidra.start()"` | Drive Ghidra from CPython without the GUI | Windows, Linux, macOS |
| `java` | `java -version` | Confirm the JDK version the Ghidra release requires | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

ifc = DecompInterface()
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()
count = 0
for f in currentProgram.getFunctionManager().getFunctions(True):
    high = ifc.decompileFunction(f, 30, monitor).getHighFunction()
    if high is None:
        continue
    for op in high.getPcodeOps():
        if op.getOpcode() == op.CALL:
            count += 1
            print(hex(f.getEntryPoint().getOffset()), f.getName(), op.getInputs()[0])
print("calls", count)
```
