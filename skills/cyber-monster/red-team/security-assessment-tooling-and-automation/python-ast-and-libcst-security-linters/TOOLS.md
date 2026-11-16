# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`python-ast-and-libcst-security-linters`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** standard `ast` (stable across 3.11+), `libcst` 1.x for CST rewrites.
- **Validation Gate:** `python -m compileall -q src` then the fixture pair with expected hit counts.
- `ast` node fields differ across Python versions (for example `Constant` replaced `Num`/`Str`), so pin the interpreter you test against.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python -m ast` | `python -m ast fixtures/positive.py` | Dump the tree for one file to confirm node shapes | Cross-platform |
| `libcst` | `python -m libcst.tool print fixtures/positive.py` | Print the CST to see how formatting is represented | Cross-platform |
| `ruff` | `ruff check --select S --output-format json src/` | Baseline security rules before writing a custom one | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import ast

class Rule(ast.NodeVisitor):
    def __init__(self, source):
        self.source = source
        self.hits = []

    def visit_Call(self, node):
        fn = node.func
        if isinstance(fn, ast.Name) and fn.id == "eval" and node.args:
            if not isinstance(node.args[0], ast.Constant):
                self.hits.append(node.lineno)
        self.generic_visit(node)

src = open("fixtures/positive.py", encoding="utf-8").read()
rule = Rule(src)
rule.visit(ast.parse(src))
print(rule.hits)
```
