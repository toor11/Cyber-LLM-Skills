# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`crisis-communication-and-escalation`](SKILL.md) | Family: **Incident Response**

Verified entry points for maintaining the communication record. These are record-keeping and message-sending tools; nothing here touches the estate. Confirm option names with `<cmd> --help` on the installed version, particularly `gh` subcommands, which change between minor releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `date` / `Get-Date` | `date -u +%Y-%m-%dT%H:%M:%SZ` | Produce the single UTC timestamp used for every clock entry, so filings and statements share one time base | Linux, macOS, Windows |
| `git` | `git commit --allow-empty -m "INC-2026-1114: fact-register snapshot <stamp>"` in a private case repo | Snapshot the fact register at each statement so contradictions are provable from history rather than memory | All |
| `gh` (CLI) | `gh issue comment <n> --body-file update.md --repo <org>/<private-case-repo>` | Post a timestamped, attributable update to a private case issue with an edit history | All |
| `openssl` | `openssl dgst -sha256 -sign case-key.pem -out update.md.sig update.md` | Sign an outbound statement so the version that was issued is verifiable later | All |
| `mail` / `sendmail` / SMTP API | `curl -sS --fail --upload-file notice.eml "smtp://relay.invalid:25"` or a provider API call | Deliver the notice and capture the server response, which is the delivery attestation | All |
| `jq` | `jq -r '.entries[]' register.json` with a `-c` CSV-style projection | Export the register extract used in an internal escalation, so the message matches the record | Linux, macOS, Windows |
| `curl` | `curl -sS -o receipt.json -w '%{http_code}' -X POST https://submission.example-regulator.invalid/api` | Capture a submission receipt with the HTTP status and response body for the filing record | All |

## Minimal Script Shape

The shape below is a read-only gate: it refuses to release an external statement that cites a register entry which is not `confirmed`, and it stamps the exact bytes that would be sent. It sends nothing.

```bash
#!/usr/bin/env bash
# statement-gate.sh - read-only. Blocks release unless every cited claim is confirmed.
set -euo pipefail

REGISTER="${REGISTER:?path to fact-register json}"
STATEMENT="${STATEMENT:?path to the draft statement markdown}"
AUDIENCE_CLASS="${AUDIENCE_CLASS:?internal | external | public}"

echo "== 1. cited claim ids in the draft =="
mapfile -t cited < <(grep -oE '\[claim:[A-Za-z0-9-]+\]' "$STATEMENT" | sed 's/\[claim://; s/\]//' | sort -u)
if [ "${#cited[@]}" -eq 0 ]; then
  echo "BLOCK: draft cites no claim ids; every disclosed claim needs one"
  exit 2
fi

echo "== 2. evidence state per cited claim =="
fail=0
for id in "${cited[@]}"; do
  state=$(jq -r --arg id "$id" '.entries[] | select(.claim_id==$id) | .evidence_state' "$REGISTER")
  printf '  %-24s %s\n' "$id" "${state:-MISSING}"
  case "${state:-MISSING}" in
    confirmed) ;;
    *) if [ "$AUDIENCE_CLASS" != "internal" ]; then fail=1; fi ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  echo "BLOCK: external statement cites a non-confirmed claim"
  exit 3
fi

echo "== 3. freeze the exact bytes that would be issued =="
sha256sum "$STATEMENT" | tee "$STATEMENT.sha256"
echo "PASS: statement may proceed to approval. Nothing was sent."
```

## Notes That Prevent Wrong Runs

- Use one timestamp source for the whole incident. A filing receipt in local time and a statement in UTC cannot be reconciled afterwards without guessing which conversion was applied.
- The register must be versioned, not overwritten. The contradiction queries depend on history; an edited register destroys the ability to show what was believed when a statement was issued.
- `--upload-file` against an SMTP endpoint returns a transport status, not a delivery confirmation. Capture the provider's message id or bounce record as the delivery attestation.
- A submission API that returns `202` has accepted the request; it has not accepted the filing. Follow the receipt endpoint until it returns a final submission identifier before recording the obligation as met.
- Signing a statement proves the bytes that were signed, and nothing about whether they were sent. Keep the signature, the send record and the approval record as three separate artefacts.
