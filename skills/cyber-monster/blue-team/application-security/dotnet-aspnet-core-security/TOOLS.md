# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dotnet-aspnet-core-security`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dotnet` | `dotnet list package --vulnerable --include-transitive` | Advisory match against the resolved package graph | Cross-platform |
| `dotnet` | `dotnet --list-runtimes` | Confirm the host carries the current servicing release | Cross-platform |
| `semgrep` | `semgrep scan --config p/csharp --error` | `FromSqlRaw`, `DtdProcessing`, and binding patterns | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H "Authorization: Bearer $TOKEN_B" -d '{"id":1,"ownerId":"attacker"}' $API/projects/1/rename` | Overposting probe | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Evidence: vulnerable packages, runtime patch level, and raw-SQL call sites.
set -euo pipefail
dotnet list package --vulnerable --include-transitive
dotnet --list-runtimes | sed -n 's/.*Microsoft.AspNetCore.App \([0-9.]*\).*/aspnet=\1/p'
grep -rn --include='*.cs' -E 'FromSqlRaw\(\$|DtdProcessing\.Parse' . || true
```

## Verification

- No vulnerable package rows, or each is dispositioned with a reachability note.
- The printed ASP.NET Core runtime is at or above the current servicing release for the target framework.
- The grep returns no composed `FromSqlRaw` and no `DtdProcessing.Parse`.
