# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`incident-response-playbooks`](SKILL.md) | Family: **Incident Response**

Verified entry points for running and evidencing an incident as a programme, not a conversation. These tools record decisions, produce a timeline, and prove the playbook was current. Nothing here touches the estate. Confirm subcommand names with `<cmd> --help`, since `gh` and `git` option sets change between minor releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `gh` (CLI) | `gh issue create --repo <org>/ir-case --title "INC-2026-1114: <summary>" --label sev2` | Open the case as an auditable object with an immutable edit history and per-action timestamps | All |
| `gh` (CLI) | `gh issue comment <n> --body-file decision.md --repo <org>/ir-case` | Record each decision and approval as a timestamped, attributable entry rather than a chat message | All |
| `git` | `git tag -a "INC-2026-1114-t0" -m "case opened"` in a private case repo | Mark phase boundaries in version control so the timeline is reconstructible from history | All |
| `jq` | `jq -r '.phases[]' case.json` | Extract phase state and artefact references for the review pack | Linux, macOS, Windows |
| `pandoc` | `pandoc review.md -o review.pdf --pdf-engine=weasyprint` | Produce the review artefact in a fixed format with a stable hash | All |
| `sha256sum` / `Get-FileHash` | `Get-FileHash -Algorithm SHA256 -Path review.pdf` | Hash the issued review so the version circulated is verifiable | All |
| `date` / `Get-Date` | `date -u +%Y-%m-%dT%H:%M:%SZ` | Single UTC source for every case timestamp, avoiding local-time conversions in the record | All |

## Minimal Script Shape

The shape below validates a case record against the playbook's own requirements and refuses to mark a phase complete without its artefact. It writes nothing except a report.

```bash
#!/usr/bin/env bash
# case-gate.sh - read-only. Refuses phase closure when the artefact is absent.
set -euo pipefail

CASE_JSON="${CASE_JSON:?path to case record}"
REQUIRED_PHASES=(triage containment eradication closure)

fail=0
for phase in "${REQUIRED_PHASES[@]}"; do
  state=$(jq -r --arg p "$phase" '.phases[] | select(.name==$p) | .state' "$CASE_JSON")
  artefact=$(jq -r --arg p "$phase" '.phases[] | select(.name==$p) | .artefact_ref // ""' "$CASE_JSON")
  owner=$(jq -r --arg p "$phase" '.phases[] | select(.name==$p) | .owner // ""' "$CASE_JSON")

  printf '%-14s state=%-10s owner=%-18s artefact=%s\n' \
    "$phase" "${state:-missing}" "${owner:-none}" "${artefact:-none}"

  if [ "${state:-missing}" = "complete" ] && [ -z "${artefact}" ]; then
    echo "  REOPEN: phase marked complete with no artefact reference"
    fail=1
  fi
done

sev_criterion=$(jq -r '.severity.criterion // ""' "$CASE_JSON")
if [ -z "$sev_criterion" ]; then
  echo "BLOCK: severity has no criterion recorded"
  fail=1
fi

echo "== authority records =="
jq -r '.actions[] | select(.approved_by == null) | "  NO APPROVAL: \(.action_type) at \(.action_utc)"' "$CASE_JSON" || true

[ "$fail" -eq 0 ] && echo "PASS: case record satisfies its own closing conditions" || echo "FAIL: see above"
```

## Notes That Prevent Wrong Runs

- A case record in a chat channel has no per-action timestamp that survives edits and no attributable author after a rename. Use an object with an edit history, and cross-reference the channel rather than relying on it.
- `gh issue comment --body-file` preserves exact bytes; pasting into a web form normalises line endings and breaks any hash taken beforehand.
- `git tag -a` requires a message and records the tagger identity, which is why it is preferable to a lightweight tag for phase boundaries.
- `pandoc` output depends on the engine and the installed font set, so the same source can produce different bytes on different hosts. Record the engine version with the hash or the hash is not reproducible.
- `date -u` in the shell and UTC formatting in the record can still disagree if a container sets a different locale; pin the format string and record it beside the case.
