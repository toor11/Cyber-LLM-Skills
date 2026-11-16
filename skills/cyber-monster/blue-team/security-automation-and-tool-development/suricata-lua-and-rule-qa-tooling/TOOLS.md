# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`suricata-lua-and-rule-qa-tooling`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `suricata --help` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Suricata 8.x (`suricata -T` load test, sandboxed Lua 5.4 detection scripts via `lua:<script>;`, `suricata-verify` PCAP cases, `eve.json` output)
- **Validation Gate:** `suricata -T -S rules/local.rules -c suricata.yaml`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `suricata` | `suricata -T -S rules/local.rules -c suricata.yaml` | Rule/config load test without running an interface | Linux/macOS (Windows via WSL) |
| `suricata` | `suricata -r fixture.pcap -S rules/local.rules -l ./out` | Replay a capture and write `eve.json` into `./out` | Linux/macOS |
| `suricata` | `suricata --build-info` | Confirm Lua support, version, and feature flags | Linux/macOS |
| `suricata-verify` | `python run.py TEST-NAME` (from the Suricata source tree) | Run one PCAP regression test that asserts on `eve.json` | Linux/macOS |
| `suricata-verify` (test.yaml) | `checks:` → `filter:` → `count:` / `match:` | Declare expected event counts and field matches | Linux/macOS |
| rule keyword | `lua:script.lua;` | Invoke a Lua detection script; scripts must define `init(args)` and `match(args)` returning `1`/`0` | Engine |
| Lua module | `require("suricata.http")` → `http.get_tx()` | Inspect the selected HTTP transaction inside the sandbox | Engine |
| rule keyword | `from_base64` transform | Base64-decode a buffer before matching; prefer over `base64_decode` in 8.x | Engine |

## Minimal Script

```powershell
suricata -T -S .\local.rules -c C:\suricata\suricata.yaml
$load = $LASTEXITCODE
if ($load -ne 0) { Write-Output "load failed: $load"; exit 2 }
suricata -r .\fixtures\malicious.pcap -S .\local.rules -c C:\suricata\suricata.yaml -l .\out-positive
suricata -r .\fixtures\benign.pcap -S .\local.rules -c C:\suricata\suricata.yaml -l .\out-benign
$pos = (Select-String -Path .\out-positive\eve.json -Pattern '"signature_id":1000201').Count
$neg = (Select-String -Path .\out-benign\eve.json -Pattern '"signature_id":1000201').Count
if ($pos -lt 1) { Write-Output "expected alert missing"; exit 1 }
if ($neg -ne 0) { Write-Output "benign fixture alerted"; exit 1 }
```

Exit-code contract: `0` loads and the differential holds, `1` rule-property violation or broken differential, `2` config/rule/PCAP missing.
