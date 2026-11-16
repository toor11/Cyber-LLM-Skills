# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`zeek-script-and-notice-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `zeek --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Zeek 8.x scripting (`@load base/frameworks/notice`, `@load base/frameworks/sumstats`, typed `record`, `SumStats::Reducer`/`create`/`observe`)
- **Validation Gate:** `zeek -Cr test.pcap local_policy.zeek`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `zeek` | `zeek -Cr fixture.pcap policy.zeek` | Replay a capture through one script without a live interface | Linux/macOS (Windows via WSL or Docker) |
| `zeek` | `zeek -r fixture.pcap` | Process a capture with the site's loaded script set | Linux/macOS |
| `zeek` | `zeek -NN Zeek::Notice` | List notice-related script components built into the binary | Linux/macOS |
| `zeek-cut` | `zeek-cut id.orig_h id.resp_h < conn.log` | Column projection from a Zeek TSV log; unique the two address columns afterward | Linux/macOS |
| `btest` | `btest -d scripts/policy/dns_tunnel` | Run the script's regression cases from its `tests/` directory | Linux/macOS |
| `zeek` (SumStats) | `SumStats::create([$name=..., $epoch=..., $reducers=set(r), $threshold=...])` | Cluster-transparent windowed aggregation | Script API |
| `zeek` (Notice) | `NOTICE([$note=..., $msg=..., $src=..., $dst=..., $identifier=...])` | Emit a routable detection into `notice.log` | Script API |
| `zeek` (tables) | `global seen: table[addr] of count &create_expire=1hr;` | Bound per-key state so worker memory stays flat | Script API |

## Minimal Script

```powershell
# Load check plus replay of one fixture; run from the script's directory.
zeek -Cr .\fixtures\dns_tunnel_positive.pcap .\policy\dns_tunnel_window.zeek
$load = $LASTEXITCODE
if ($load -ne 0) { Write-Output "zeek load/replay failed: $load"; exit 2 }
Get-Content .\notice.log -ErrorAction SilentlyContinue |
  Select-String -Pattern 'DNS_Tunnel_Window' |
  ForEach-Object { $_.Line }
```

Exit-code contract for the wrapper: `0` notice appeared on the positive fixture and not on the benign one, `1` differential broken, `2` script failed to load or fixture missing.
