# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`capstone-and-lief-binary-inspector-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** LIEF 0.x (`lief.parse`, `has_nx`, `is_pie`, `imported_functions`), Capstone 5.x with explicit arch and mode.
- **Validation Gate:** `python -c "import lief, capstone; print(lief.__version__, capstone.__version__)"` plus one parse with the file hash printed.
- Always pass the virtual address to `disasm`; letting Capstone number from zero produces addresses that cannot be matched to the binary.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `LIEF` | `python -c "import lief; print(lief.__version__)"` | Pin the parser version whose header property names you rely on | Cross-platform |
| `Capstone` | `python -c "import capstone; print(capstone.__version__)"` | Confirm decoder version before quoting mnemonics | Cross-platform |
| `pefile` | `python -c "import pefile; print(pefile.__version__)"` | Cross-check PE header fields independently of LIEF | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import hashlib
import lief
import capstone

path = "app.exe"
print(hashlib.sha256(open(path, "rb").read()).hexdigest())
binary = lief.parse(path)
print(binary.header.machine_type, "nx", binary.has_nx, "pie", binary.is_pie)
func = next((s for s in binary.symbols if s.name == "parse_record"), None)
if func is not None:
    code = bytes(binary.get_content_from_virtual_address(func.value, func.size))
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for insn in md.disasm(code, func.value):
        print(hex(insn.address), insn.mnemonic, insn.op_str)
```
