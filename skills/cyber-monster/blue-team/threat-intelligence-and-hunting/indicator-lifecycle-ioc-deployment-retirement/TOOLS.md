# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`indicator-lifecycle-ioc-deployment-retirement`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +short cdn-update.example.net @$RESOLVER` | Confirm the resolver answers with the sinkhole or NXDOMAIN | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code}\n' -x $PROXY https://cdn-update.example.net` | Proxy enforcement probe | Cross-platform |
| `siem` | `index=proxy dest_host=cdn-update.example.net` with `stats count by src` | Hit history per deployment | Cross-platform |
| `git` | `git log -p -- indicators/deployed/` | Deployment and retirement history | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```bash
#!/usr/bin/env bash
# Deployment verification: probe each control that should see the indicator.
set -uo pipefail
ind=${1:?indicator}; resolver=${RESOLVER:-127.0.0.53}; proxy=${PROXY:-}
printf '== dns ==\n'
dig +short "$ind" "@$resolver" || true
printf '== proxy ==\n'
if [ -n "$proxy" ]; then
  curl -sS -o /dev/null -w '%{http_code}\n' -x "$proxy" "https://$ind" || true
else
  echo "no proxy configured; deployment unverified"
fi
printf '== hit history ==\n'
grep -c "$ind" hits.txt 2>/dev/null || echo 0
```

## Verification

- The DNS answer shows a sinkhole or NXDOMAIN, which proves enforcement rather than configuration.
- The proxy status is a deny page or 403, proving the second control independently.
- The hit count is non-zero or explicitly zero with a coverage note, so untested enforcement is visible.
