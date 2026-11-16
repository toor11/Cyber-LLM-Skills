# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`supply-chain-incident-response`](SKILL.md) | Family: **Incident Response**

Verified inventory and provenance tooling. Every command reads resolution state or audit records; none installs, upgrades or executes an affected package. Confirm flags with `<tool> --help` — package managers change lifecycle-hook defaults between majors.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `npm ls` | `npm ls <pkg> --all --json` | Resolved tree from the installed state without fetching anything | Cross-platform |
| `npm ci` | `npm ci --ignore-scripts --dry-run` | Resolve the lockfile without running lifecycle hooks or writing `node_modules` | Cross-platform |
| `pnpm` | `pnpm list --depth Infinity --json` | Resolution view; pnpm 11's built-in 24-hour minimum release age blocks fresh versions by default | Cross-platform |
| `syft` | `syft <image> -o spdx-json > sbom.json` | SBOM generation from an image to enumerate resolved components | Cross-platform |
| `grype` | `grype sbom:sbom.json --only-fixed` | Match an SBOM against advisory data without pulling packages | Cross-platform |
| `aws cloudtrail lookup-events` | `aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<runner>` | What an affected runner identity actually did | Cross-platform |

## Minimal Script Shape

The shape below produces an exposure matrix that distinguishes resolved, fetched and executed, and refuses to emit a "not affected" verdict when a coverage window is too short. It installs nothing.

```bash
#!/usr/bin/env bash
# scm-exposure.sh — resolution / fetch / execution, three columns, no installs.
set -euo pipefail

REPO_ROOT="${REPO_ROOT:?set REPO_ROOT}"
CAMPAIGN_START="${CAMPAIGN_START:?set CAMPAIGN_START (UTC ISO8601)}"
CAMPAIGN_END="${CAMPAIGN_END:?set CAMPAIGN_END (UTC ISO8601)}"
AFFECTED="${AFFECTED:?set AFFECTED as 'pkg@version pkg@version ...'}"
OUT="${OUT:-./scm-exposure.csv}"

echo "repo,lockfile,resolved,fetched,executed,verdict" > "$OUT"

find "$REPO_ROOT" -maxdepth 4 -type f \
  \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' \) -print |
while IFS= read -r lock; do
  repo="$(dirname "$lock")"
  for pkg in $AFFECTED; do
    name="${pkg%@*}"; ver="${pkg##*@}"
    if grep -Fq -- "\"$name\"" "$lock" 2>/dev/null && grep -Fq -- "$ver" "$lock" 2>/dev/null; then
      resolved="yes"
    else
      resolved="no"
    fi

    # Fetch and execution are environment facts, not repository facts.
    # They must be supplied by the proxy export and the runner process export.
    fetched="${FETCH_LOOKUP:-unknown}"
    executed="${EXEC_LOOKUP:-unknown}"

    verdict="$(python3 - "$resolved" "$fetched" "$executed" <<'PY'
import sys
r, f, e = sys.argv[1:4]
if r == "no":
    print("not resolved - manifest range only, no exposure")
elif f == "unknown" or e == "unknown":
    print("INCONCLUSIVE - coverage window or proxy/process export missing")
elif e == "yes":
    print("EXECUTED - treat identity as credential-compromised, rotate before rebuild")
elif f == "yes":
    print("FETCHED - artifact present; confirm install-script setting per environment")
else:
    print("RESOLVED ONLY - not fetched in window; pin a clean version")
PY
)"
    printf '%s,%s,%s,%s,%s,"%s"\n' "$repo" "$(basename "$lock")" "$resolved" "$fetched" "$executed" "$verdict" >> "$OUT"
  done
done

# Coverage gate: refuse a clean conclusion when the window is unanswerable.
if [ "${CI_HISTORY_START:-}" \< "$CAMPAIGN_START" ] 2>/dev/null; then
  echo "GAP: CI history begins after the campaign window -> exposure is INCONCLUSIVE, not negative"
  exit 3
fi
echo "wrote $OUT"
```

## Notes That Prevent Wrong Runs

- `npm ci --dry-run` still resolves the full tree. It is the safest way to confirm what a lockfile pins, but confirm on the installed package manager version — older releases treat `--dry-run` inconsistently.
- `--ignore-scripts` changes what happens at install; it does not change what the lockfile resolves. An environment that used it was exposed to the artifact but not to its hook, and the report must say that precisely.
- A package version is not immutable in practice. Where a registry allows republishing, a version string can point at different bytes over time, so hash comparison against an advisory's published digest is the only reliable check.
- `syft` on an image describes what is inside it. An image built before the campaign and rebuilt after may contain different bytes under the same tag; record the image digest, not the tag.
- Long-window hunts against Defender XDR tables can silently return nothing when the table is routed only to the Microsoft Sentinel data lake — lake-only tables are invisible to Sentinel analytics rules and the Logs blade. Query the lake endpoint and record which one you used.
