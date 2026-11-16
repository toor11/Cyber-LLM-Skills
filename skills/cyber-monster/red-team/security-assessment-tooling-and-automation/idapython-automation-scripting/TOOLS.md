# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`idapython-automation-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** IDA Pro 9.x IDAPython; `ida_hexrays` requires the decompiler licence.
- **Validation Gate:** `idat -A -Saudit.py target.i64` completes with exit status 0 and the script's log file is non-empty.
- Hex-Rays ctree APIs are versioned; guard `ida_hexrays.init_hexrays_plugin()` before calling decompile.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `idat` | `idat -A -Saudit.py target.i64` | Batch-mode script execution against a database | Windows, Linux, macOS |
| `idapyswitch` | `idapyswitch --show-current` | Confirm the Python version IDA will use, which decides available modules | Windows, Linux, macOS |
| `ida_hexrays` | `python -c "import ida_hexrays; print(ida_hexrays.get_hexrays_version())"` | Check decompiler availability inside the IDA console | Windows, Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import ida_auto, ida_funcs, idautils, idc

ida_auto.auto_wait()
target = idc.get_name_ea_simple("memcpy")
rows = []
if target != idc.BADADDR:
    for xref in idautils.XrefsTo(target, 0):
        func = ida_funcs.get_func(xref.frm)
        if func is not None:
            rows.append((hex(xref.frm), idc.get_func_name(func.start_ea)))
print(len(rows))
for r in rows[:20]:
    print(*r)
```
