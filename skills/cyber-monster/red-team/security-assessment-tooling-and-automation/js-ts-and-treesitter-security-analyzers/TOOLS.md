# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`js-ts-and-treesitter-security-analyzers`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** tree-sitter 0.2x with grammar packages, or ESLint 9 flat config for pipeline integration.
- **Validation Gate:** `python -c "import tree_sitter_javascript"` plus a positive/negative fixture pair with printed captures.
- Query syntax is grammar-specific: `member_expression` in JavaScript is not the node you get in TypeScript for the same source.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `tree-sitter` | `tree-sitter parse sample.js` | Print the concrete syntax tree to confirm node names before writing a query | Cross-platform |
| `eslint` | `npx eslint --format json src/` | Run the rule inside the project's existing pipeline | Cross-platform |
| `node` | `node -e "console.log(require('tree-sitter').VERSION)"` | Confirm the runtime binding version | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Parser, Query, QueryCursor

lang = Language(tsjs.language())
parser = Parser(lang)
query = Query(lang, "(call_expression function: (identifier) @fn arguments: (arguments (_) @arg))")
tree = parser.parse(open("sample.js", "rb").read())
rows = []
for _, caps in QueryCursor(query).matches(tree.root_node):
    if caps["fn"][0].text == b"eval":
        rows.append((caps["arg"][0].start_point, caps["arg"][0].text[:40]))
print(rows)
```
