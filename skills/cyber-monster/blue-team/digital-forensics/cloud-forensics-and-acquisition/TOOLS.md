# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`cloud-forensics-and-acquisition`](SKILL.md) | Family: **Digital Forensics**

Collection entry points for cloud evidence. Never invent undocumented flags — confirm with `aws <service> help` on the installed CLI, because subcommand names and pagination defaults change between major releases. Every command here reads or snapshots; none terminates, detaches, resizes or alters policy on a source resource.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `aws cloudtrail` | `aws cloudtrail lookup-events --start-time --end-time --lookup-attributes` | Bounded control-plane export with principal and source preserved | Cross-platform |
| `aws cloudtrail validate-logs` | `aws cloudtrail validate-logs --trail-name <t> --start-time --end-time` | Verify delivered log files against signed digest files | Cross-platform |
| `aws ec2 create-snapshot` | `aws ec2 create-snapshot --volume-id <id> --description --tag-specifications` | Capture a volume without touching the running instance | Cross-platform |
| `aws s3api` | `aws s3api get-object-lock-configuration --bucket <b>` | Read the immutability state of the evidence bucket | Cross-platform |
| `dc3dd` / `dcfldd` | `dc3dd if=/dev/nvme1n1 of=/evidence/vol.dd hash=sha256 log=vol.log` | Stream a restored volume to a hashed image before mounting | Linux |
| `aws logs filter-log-events` | `aws logs filter-log-events --log-group-name <g> --start-time --end-time --filter-pattern` | Bounded flow-log or application-log retrieval | Cross-platform |

## Minimal Script Shape

The shape below establishes coverage and integrity first, and exits with a distinct code when the trail cannot support the conclusion, so an automated pipeline cannot silently publish a "clean" result built on absent data.

```bash
#!/usr/bin/env bash
# cloud-evidence-gate.sh — read-only coverage and integrity gate.
set -euo pipefail

REGION="${REGION:?set REGION}"
TRAIL="${TRAIL:?set TRAIL}"
START="${START:?ISO8601 UTC}"
END="${END:?ISO8601 UTC}"
CASE="${CASE:?set CASE}"

sel=$(aws cloudtrail get-event-selectors --trail-name "$TRAIL" --region "$REGION" --output json)
valid=$(aws cloudtrail describe-trails --region "$REGION" \
  --trail-name-list "$TRAIL" --query 'trailList[0].LogFileValidationEnabled' --output text)
multi=$(aws cloudtrail describe-trails --region "$REGION" \
  --trail-name-list "$TRAIL" --query 'trailList[0].IsMultiRegionTrail' --output text)

printf 'case=%s trail=%s region=%s multi_region=%s validation=%s\n' \
  "$CASE" "$TRAIL" "$REGION" "$multi" "$valid"

[ "$valid" = "True" ] || { echo "GAP: log validation disabled -> INCONCLUSIVE"; exit 3; }
[ "$multi" = "True" ] || { echo "NOTE: single-Region trail; state the gap per Region"; }

aws cloudtrail validate-logs --trail-name "$TRAIL" --region "$REGION" \
  --start-time "$START" --end-time "$END" \
  || { echo "GAP: digest validation failed -> INCONCLUSIVE for this range"; exit 4; }

echo "$sel" | jq -r '.EventSelectors[] | "read_write=\(.ReadWriteType) data=\(.DataResources//[]|length)"'
echo "coverage gate passed; proceed to bounded lookup-events for the window"
```

## Notes That Prevent Wrong Runs

- `lookup-events` is bounded by event-history retention (90 days of management events per Region) and cannot see data events. For older windows or object-level questions you must read the trail's S3 prefix directly, after validating the digests.
- Snapshot creation is asynchronous. Poll `describe-snapshots` for `State: completed` before restoring; a `pending` snapshot restored to a volume yields a truncated filesystem that reads exactly like deliberate wiping.
- A snapshot encrypted with a customer-managed KMS key cannot be mounted in another account until it is copied with `--kms-key-id` for that account. Record both the original and copy key IDs.
- Restore to a volume in the isolated forensics account, mount read-only, and image it before analysis. Attaching an analysis instance's volume in the source account lets the suspect principal see the investigation in CloudTrail.
- Record the identity that ran each command. The collector's own API calls appear in the trail and are the audit evidence that the acquisition itself was untampered.
