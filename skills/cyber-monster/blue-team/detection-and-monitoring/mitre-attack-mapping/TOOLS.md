# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`mitre-attack-mapping`](SKILL.md) | Family: **Detection and Monitoring**

Verified entry points for resolving technique IDs, scoring visibility and producing Navigator layers. Never invent flags or library methods — run `--help` against the installed version, because the DeTT&CT argument set and the STIX bundle layout change between ATT&CK releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| DeTT&CT (data sources) | `python dettect.py ds -fd data-sources-endpoints.yaml -l` | Emit a Navigator layer from scored data sources, giving rough visibility coverage before any rule mapping | Cross-platform (Python 3) |
| DeTT&CT (detections) | `python dettect.py d -ft techniques-administration-endpoints.yaml -l` | Emit a Navigator layer from scored detections per technique, with `score_logbook` history | Cross-platform (Python 3) |
| DeTT&CT (export) | `python dettect.py ds -fd data-sources-endpoints.yaml -e` | Produce an Excel administration sheet for review rather than a layer | Cross-platform (Python 3) |
| `jq` on the STIX bundle | `jq -r 'map(select(.type=="attack-pattern"))[].external_references[0].external_id' enterprise-attack-v19.json` applied to the `.objects` array | List every technique ID in the pinned release for resolution checks | Linux, macOS, Windows |
| `jq` on a layer | `jq -e '.versions.layer == "4.5"' layer.json` | Reject a layer with a bad schema version before import; combine with the ID regex check in the script below | Linux, macOS, Windows |
| `stix2` (Python) | `from stix2 import MemoryStore, Filter` then `Filter("attack-pattern")` | Query the ATT&CK bundle programmatically when jq is not enough | Cross-platform (Python 3) |
| `sigma` rule tags | `rg -o --no-filename 'attack\.t[0-9]{4}(\.[0-9]{3})?' rules/` then `sort -u` | Extract the technique set the rule corpus actually claims | Linux, macOS, Windows |

## Minimal Script Shape

The shape below is the smallest defensible coverage computation: it resolves the claimed IDs against a pinned release, drops revoked entries, and reports coverage against an environment-specific denominator instead of the full catalogue.

```bash
#!/usr/bin/env bash
# coverage.py-equivalent in bash+jq: claimed IDs vs pinned release vs relevant set.
set -euo pipefail

BUNDLE="${BUNDLE:?path to enterprise-attack-<version>.json}"
RULES_DIR="${RULES_DIR:-./rules}"
RELEVANT="${RELEVANT:-./relevant-techniques.txt}"

# 0. Pin the version explicitly; an unpinned layer cannot be compared later.
jq -r '.spec_version' "$BUNDLE" >/dev/null
VERSION=$(jq -r '[.objects[] | select(.type=="x-mitre-collection") | .x_mitre_version][0] // "unknown"' "$BUNDLE")
echo "attack_bundle_version=${VERSION}"

# 1. Claimed IDs from rule tags.
rg -o --no-filename 'attack\.t[0-9]{4}(\.[0-9]{3})?' "$RULES_DIR" \
  | sed 's/^attack\.//' | tr 'a-z' 'A-Z' | sort -u > /tmp/claimed.txt

# 2. Known, non-revoked IDs from the pinned release.
jq -r '.objects[]
       | select(.type=="attack-pattern")
       | select(.revoked != true)
       | .external_references[0].external_id' "$BUNDLE" | sort -u > /tmp/known.txt

# 3. Resolve: claimed but unknown means the mapping is stale, not covered.
comm -23 /tmp/claimed.txt /tmp/known.txt > /tmp/unresolved.txt
echo "unresolved_claims=$(wc -l < /tmp/unresolved.txt)"

# 4. Coverage against the relevant set only.
sort -u "$RELEVANT" > /tmp/relevant.txt
comm -12 /tmp/claimed.txt /tmp/relevant.txt > /tmp/covered.txt
echo "covered=$(wc -l < /tmp/covered.txt) of relevant=$(wc -l < /tmp/relevant.txt)"
echo "gaps:"; comm -23 /tmp/relevant.txt /tmp/covered.txt
```

## Notes That Prevent Wrong Runs

- DeTT&CT scores are 0–4 and multiple `score` objects in a `score_logbook` record history. Reporting only the latest score destroys the movement trend, which is the part stakeholders act on.
- A Navigator layer's `techniqueID` values must be strings; numeric IDs lose leading zeros in sub-technique numbers and silently fail to render.
- The STIX bundle keeps revoked techniques. `select(.revoked != true)` is mandatory or `T1562` will look valid forever.
- `comm` requires sorted input on both sides and compares bytewise; without a consistent `sort` locale, valid IDs appear as gaps.
