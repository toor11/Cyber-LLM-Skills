# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`api-security-review`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `schemathesis` | `schemathesis run openapi.json --base-url https://staging --checks all --hypothesis-max-examples 50` | Property-based checks from the schema, including auth responses | Cross-platform |
| `k6` | `k6 run --vus 20 --duration 30s ratelimit.js` | Test whether limits hold across concurrent requests rather than sequentially | Cross-platform |
| `jq` | `jq -r '.paths' openapi.json` | Enumerate documented paths for diffing against the route table | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' -H "Authorization: Bearer $A" https://staging/v1/invoices/$FOREIGN_ID` | Two-tenant probe with a comparable response shape | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Two-tenant differential: foreign id and missing id must be indistinguishable.
set -uo pipefail
api=${API:?}; a=${TOKEN_A:?}
for id in "$FOREIGN_ID" "00000000-0000-0000-0000-000000000000"; do
  printf '%s -> ' "$id"
  curl -sS -o /tmp/body -w '%{http_code} %{size_download} %{time_total}\n' \
    -H "Authorization: Bearer $a" "$api/v1/invoices/$id"
done
# identical status+size on both lines is the pass condition
diff <(xargs -n1 <<<"$FOREIGN_ID") <(echo "00000000-0000-0000-0000-000000000000") >/dev/null || true
```

## Verification

- Both probe lines show the same status and a comparable body size; a size gap means the response distinguishes existence.
- Timing difference between the two lines stays within noise; a consistent gap is an oracle even when the status matches.
- The same script run with tenant B's token returns B's object, proving the probe mechanism works.
