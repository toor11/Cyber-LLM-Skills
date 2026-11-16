# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`containment-and-eradication`](SKILL.md) | Family: **Incident Response**

Verified verification entry points for containment and eradication. Everything below reads state or lists objects; the two state-changing calls are marked and shown with their dry-run or confirmation surface. Never invent flags — check `<cmd> --help`, since `nft`, `iptables` and `Get-MpComputerStatus` option sets differ by platform and build.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| Microsoft Defender (PowerShell) | `Get-MpComputerStatus -CimSession <session>` | Confirm the endpoint protection agent is present, current and not in a degraded state, which is a precondition for agent-enforced isolation | Windows |
| `netsh` | `netsh advfirewall show allprofiles` | Read the host firewall profile state to verify that an isolation rule is not the only thing blocking egress | Windows |
| `nft` / `iptables` | `nft list ruleset` or `iptables -S` | Read the packet-filter ruleset to confirm which egress paths are actually dropped | Linux |
| `ss` / `Get-NetTCPConnection` | `ss -tunap state established` or `Get-NetTCPConnection -State Established` | Enumerate live connections on the contained asset; an established session to the actor survives many isolation mechanisms | Linux, Windows |
| `Get-Service` / `systemctl` | `Get-Service -Name * -ErrorAction SilentlyContinue` then filter with `Where-Object Status` | Detect newly created or re-created services after eradication | Windows, Linux |
| `schtasks` / `systemctl list-timers` | `schtasks /query /fo LIST /v` or `systemctl list-timers --all` | Enumerate scheduled execution that can re-create the implant | Windows, Linux |
| `sha256sum` / `Get-FileHash` | `Get-FileHash -Algorithm SHA256 -Path <evidence>` | Hash preserved evidence so the containment record is defensible | All |

## Minimal Script Shape

The shape below is a read-only containment post-check: it records whether the asset is genuinely contained from its own perspective, and whether a credential-bearing session is still live. Nothing is blocked or changed.

```bash
#!/usr/bin/env bash
# containment-verify.sh - read-only. Run on or against the contained asset.
set -uo pipefail

OUT="${OUT_DIR:?output directory}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT/../$STAMP" 2>/dev/null || true
DEST="$OUT/containment-$STAMP"
mkdir -p "$DEST"

echo "== 1. live connections (an established session can outlive an isolation rule) =="
ss -tunap state established > "$DEST/established.txt" 2>/dev/null || true
cat "$DEST/established.txt"

echo "== 2. packet filter state (which egress is actually dropped) =="
if command -v nft >/dev/null 2>&1; then
    nft list ruleset > "$DEST/ruleset.txt"
elif command -v iptables >/dev/null 2>&1; then
    iptables -S > "$DEST/ruleset.txt"
else
    echo "no packet filter tooling found" > "$DEST/ruleset.txt"
fi

echo "== 3. newly armed persistence (compare against the pre-containment baseline) =="
systemctl list-timers --all > "$DEST/timers.txt" 2>/dev/null || true
ls -la /etc/cron.d /etc/systemd/system 2>/dev/null > "$DEST/persistence-dirs.txt" || true

echo "== 4. freeze the observation =="
( cd "$DEST" && sha256sum ./* > SHA256SUMS 2>/dev/null ) || true
echo "written: $DEST"
```

## Notes That Prevent Wrong Runs

- An isolation rule blocks new flows, not established ones. `ss`/`Get-NetTCPConnection` after isolation is the only cheap way to see whether the actor's session survived the containment.
- `netsh advfirewall show allprofiles` reports profile state, not rule effectiveness. A rule scoped to the wrong profile appears present and drops nothing; read the rule list for the profile in use.
- `schtasks /query /v` output is enormous and locale-dependent. Scope to a folder or filter on the task's author and run-as account rather than reading it whole.
- Agent-enforced isolation depends on the agent being healthy. A host whose agent has not checked in for hours cannot be isolated by that channel, and the containment record must say so rather than assume the console action landed.
- Hashing evidence after a rebuild proves nothing about the original state. Hash before the state changes; a hash taken afterwards is a record of the rebuilt system.
