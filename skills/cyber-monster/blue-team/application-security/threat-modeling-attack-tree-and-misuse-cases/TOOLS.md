# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`threat-modeling-attack-tree-and-misuse-cases`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `graphviz` | `dot -Tsvg tree.dot -o tree.svg` | Render the AND/OR structure so reviewers can see shared controls | Cross-platform |
| `attacktree` (Python) | `python -m attacktree render tree.yml --format mermaid` | Keep the tree as data that can be diffed | Cross-platform |
| `rg` | `rg -n 'policy_scope' src/` | Verify that a cited break point exists | Cross-platform |
| `git` | `git log -1 --format=%H -- threat-model/tree.yml` | Bind the tree to a revision | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```yaml
# Tree as data: every path must reach a leaf carrying a break point.
goal: read another tenant's invoices
operator: OR
children:
  - goal: use own session on a foreign object
    operator: AND
    children:
      - {leaf: know object id, break: "tenant predicate InvoiceRepo.get", located: true}
      - {leaf: batch skips per-item scope, break: "MISSING", located: false}
  - goal: obtain a foreign session
    operator: OR
    children:
      - {leaf: reusable reset token, break: "auth/reset.py:31 consume_once", located: true}
```

## Verification

- Every `located: false` entry is a finding with an owner; the file is the finding list, not documentation.
- Rendering the YAML produces a tree where each root-to-leaf path shows at least one break point.
- Re-running after the fix flips `located` to true and the finding closes with a code reference.
