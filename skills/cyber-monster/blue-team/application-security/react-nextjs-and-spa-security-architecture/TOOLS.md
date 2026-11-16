# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`react-nextjs-and-spa-security-architecture`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `npm` | `npm ls next react --all` | Resolved framework versions for advisory matching | Cross-platform |
| `semgrep` | `semgrep scan --config p/react --config p/javascript --error` | Raw-HTML sinks and directive patterns | Cross-platform |
| `curl` | `curl -sS -X POST -H 'Next-Action: <id>' -H 'content-type: application/json' --data @body.json https://staging/` | Replay a Server Action directly, bypassing the UI | Cross-platform |
| `playwright` | `npx playwright test tests/authz.spec.ts` | Encode the boundary probe as a browser test | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Evidence: action inventory, taint usage, and framework version.
set -euo pipefail
grep -rln "'use server'" --include='*.ts' --include='*.tsx' app src | sed 's/^/action file: /'
grep -rn "dangerouslySetInnerHTML\|taintUniqueValue\|NEXT_PUBLIC_" --include='*.tsx' --include='*.ts' app src || true
node -e "const l=require('./package-lock.json');for (const k of ['next','react']) console.log(k, l.packages['node_modules/'+k]?.version)"
```

## Verification

- Every listed action file is opened and checked for an in-body session read; the grep is the inventory, not the verdict.
- No `NEXT_PUBLIC_` variable holds a secret, which is the most common boundary leak.
- The printed `next` version is compared against the 2026 advisory ranges before sign-off.
