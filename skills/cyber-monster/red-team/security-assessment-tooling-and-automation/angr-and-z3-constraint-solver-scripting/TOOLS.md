# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`angr-and-z3-constraint-solver-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** angr 9.x (`Project`, `factory.entry_state`, `simgr.explore`), claripy for symbolic values, z3 4.x for standalone models.
- **Validation Gate:** `python -c "import angr, z3; print(angr.__version__)"` plus one concrete replay of every model.
- `auto_load_libs=False` keeps the state space small on dynamically linked targets; enable it only when a library check is the guard under test.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `angr` | `python -m angr ./validator 0x401234` | Reachability probe against a single guard address | Cross-platform |
| `z3` | `python -c "import z3; print(z3.get_version_string())"` | Confirm solver version before trusting a timeout result | Cross-platform |
| `python` | `python -m py_compile probe.py` | Syntax-check the harness before a long symbolic run | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import angr
import z3

SUCCESS, ERROR = 0x401234, 0x401300
proj = angr.Project("./validator", auto_load_libs=False)
state = proj.factory.entry_state(stdin=angr.SimFileStream)
simgr = proj.factory.simgr(state)
simgr.explore(find=SUCCESS, avoid=ERROR, num_find=1)
if simgr.found:
    found = simgr.found[0]
    data = found.solver.eval(found.posix.stdin.load(0, found.posix.stdin.size), cast_to=bytes)
    print(data.hex())
else:
    print("no model within budget: treat as unsat-under-model, not proven safe")
```
