# Detection Queries and Telemetry Artifacts

> Sub-skill: [`zeek-script-and-notice-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Script, notice, and aggregation artifacts owned by this slug. Verify field names against the installed Zeek version's script reference before deployment.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | `notice.log` entry with `note` = site-declared `Notice::Type` | High | The detection reached the notice framework with a routable type |
| 2 | `SumStats::create()` with a non-zero `epoch` | High | Aggregation is cluster-transparent and bounded by a time window |
| 3 | Global `table[addr] of count` with `&create_expire` | Medium | Per-source state cannot grow with capture length |
| 4 | `zeek -Cr fixture.pcap policy.zeek` exit status | High | The script compiles and loads; a load error invalidates all assertions |
| 5 | `conn.log`/`dns.log` fields referenced by the script present in output | Medium | The analyzer providing those fields is actually loaded |

## Detection Artifacts

```text
[zeek-script-and-notice-development:rule-spec] notice.log note=<Declared::Type> src=<actor> dst=<victim> identifier=<uid>
[zeek-script-and-notice-development:filter-fp] exclude authorized scanners via Notice::policy suppression before tuning thresholds
[zeek-script-and-notice-development:correlate] SumStats reducer keyed on orig_h within epoch window
```

Replay gate against a positive fixture (Windows PowerShell 5.1):

```powershell
Set-Location C:\zeek\spool\scripts
zeek -Cr .\fixtures\dns_tunnel_positive.pcap .\policy\dns_tunnel_window.zeek
$replay = $LASTEXITCODE
if ($replay -ne 0) { Write-Output "script load failed: $replay"; exit 2 }
Get-Content .\notice.log | Select-String -Pattern 'DNS_Tunnel_Window'
```

Benign control run, which must produce no matching notice:

```powershell
zeek -Cr .\fixtures\dns_benign.pcap .\policy\dns_tunnel_window.zeek
if (Select-String -Path .\notice.log -Pattern 'DNS_Tunnel_Window' -Quiet) {
  Write-Output "false positive on benign fixture"
  exit 1
}
```

`btest` case pair so the differential runs in CI:

```text
# scripts/policy/dns_tunnel/tests/positive.test
# @TEST-EXEC: zeek -Cr $TRACES/dns_tunnel_positive.pcap %INPUT
# @TEST-EXEC: btest-diff notice.log
```

```text
# scripts/policy/dns_tunnel/tests/benign.test
# @TEST-EXEC: zeek -Cr $TRACES/dns_benign.pcap %INPUT
# @TEST-EXEC: btest-diff notice.log
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Confirm `Notice::policy` escalates the declared type on the target cluster; an un-routed type writes `notice.log` and never pages.
- Re-run the cluster check after any threshold change, since per-worker state can mask the effect at scale.
