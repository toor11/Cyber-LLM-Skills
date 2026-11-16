# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-and-web-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for reading the engine's configuration and audit output. Never invent directive names or CRS variable names — read them from the deployed `crs-setup.conf` and the engine's documentation for the installed version.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `apachectl` / `nginx -t` | `apachectl configtest` and `nginx -t` | Validate the engine's vhost configuration after any directive change | Linux |
| `apachectl -M` | `apachectl -M` piped to a grep for the engine module | Confirm the module is loaded on that vhost at all | Linux |
| `crs-setup.conf` inspection | grep for `tx.blocking_paranoia_level`, `tx.detection_paranoia_level`, `tx.inbound_anomaly_score_threshold` | Read which rule set contributes and what threshold acts, before judging any miss | Linux |
| ModSecurity audit log | Read the `H`, `B` and `K` sections for one transaction id | Full request context and rule attribution for a single request | Linux |
| `curl` (authorised probe) | `curl -sS -o /dev/null -w '%{http_code}\n' "https://staging/files/x%3Bid"` | Verify a path-borne payload produces the expected rule family on a staging build | Linux, macOS, Windows |
| `jq` | Filter the JSON audit log to `transaction.messages` rule IDs and `transaction.request.uri` | Extract rule attribution without reading raw audit sections | Linux, macOS, Windows |
| CRS container | `docker run -e PARANOIA=2 -e INBOUND_ANOMALY_SCORE_THRESHOLD=5 owasp/modsecurity-crs:4.25-lts-nginx` | Reproduce a verdict on a pinned CRS release in a lab | Linux, macOS |

## Minimal Script Shape

The shape below is the minimum defensible WAF check: read the active thresholds, then reconcile a sample of verdicts against the origin log so a block is proven effective rather than assumed.

```bash
#!/usr/bin/env bash
# waf-reconcile.sh — threshold gate, then verdict-to-origin reconciliation.
set -euo pipefail

CRS_SETUP="${CRS_SETUP:-/etc/modsecurity.d/crs-setup.conf}"
WAF_LOG="${WAF_LOG:-/var/log/modsec_audit.log}"
ORIGIN_LOG="${ORIGIN_LOG:-/var/log/nginx/access.log}"

# 0. Configuration gate: without these values a "miss" cannot be interpreted.
grep -E 'blocking_paranoia_level|detection_paranoia_level|inbound_anomaly_score_threshold' \
  "$CRS_SETUP" | sed 's/^[[:space:]]*//'

# 1. Verdict and score per request from the JSON audit format.
jq -c 'select(.transaction.is_interrupted == true)
       | {id: .transaction.id,
          uri: .transaction.request.uri,
          rules: [.transaction.messages[].details.ruleId] | unique}' \
  "$WAF_LOG" 2>/dev/null | tail -20

# 2. Reconciliation: a blocked request must have no origin entry for the same URI.
while read -r uri; do
  if grep -qF -- "$uri" "$ORIGIN_LOG"; then
    echo "MISMATCH: blocked in WAF but served by origin -> $uri"
  else
    echo "ok(blocked): $uri"
  fi
done < <(jq -r 'select(.transaction.is_interrupted == true) | .transaction.request.uri' "$WAF_LOG" 2>/dev/null | sort -u | head -20)
```

## Notes That Prevent Wrong Runs

- The audit log's JSON format must be configured; the native format needs section parsing and is easy to misread. Check the log-format directive before writing a parser.
- `tx.paranoia_level` from CRS 3 was renamed to `tx.blocking_paranoia_level` in CRS 4. Inspecting the old variable on a CRS 4 deployment returns nothing.
- The audit-log parts directive controls which sections are written; without the body part enabled, body-borne payloads are simply not in the log.
- A probe against production changes request counts and may trigger real blocks. Run it against staging with the same CRS release, and record the release tag used.
