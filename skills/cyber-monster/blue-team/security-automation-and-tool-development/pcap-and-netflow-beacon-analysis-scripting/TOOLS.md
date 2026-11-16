# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`pcap-and-netflow-beacon-analysis-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Verified tools, exact CLI flags, and SDK packages serving this sub-skill. Never invent undocumented flags — run `tshark -h` on the installed release if behaviour differs.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python 3.11 `dpkt` (`dpkt.pcap.Reader`, `dpkt.pcapng.Reader`, `dpkt.ethernet.Ethernet`, `dpkt.ip.IP`, `dpkt.tcp.TCP`), `scapy.PcapReader` when richer decoding is required, `statistics` for dispersion, `math.log2` for Shannon entropy
- **Never:** `scapy.all.rdpcap` on production captures
- **Validation Gate:** `python -m py_compile beacon_analyze.py`

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dpkt` | `dpkt.pcap.Reader(fh)` | Stream `(timestamp, buffer)` pairs from a pcap | Python >= 3.9 |
| `dpkt` | `dpkt.pcapng.Reader(fh)` | Read pcapng captures | Python |
| `dpkt` | `dpkt.ethernet.Ethernet(buf)` then `.data` chain | Decode layers without copying packets | Python |
| `scapy` | `PcapReader(path)` context manager | Stream packets with rich layer access (slower than dpkt) | Python |
| Python `statistics` | `statistics.fmean(deltas)`, `statistics.stdev(deltas)` | Mean and standard deviation of inter-arrival deltas | Python 3.11+ |
| `tshark` | `tshark -r capture.pcap -Y "<display filter>" -T fields -e <field>` | Independent field extraction for cross-checking | Cross-platform |
| `tshark` | `tshark -r capture.pcap -q -z io,stat,60` | Per-minute traffic summary | Cross-platform |
| `capinfos` | `capinfos capture.pcap` | Capture window, packet count, link type | Cross-platform |

## Minimal Script

```powershell
capinfos .\evidence\net\capture.pcap | Select-String -Pattern 'Capture duration|Packet size limit'
if ($LASTEXITCODE -ne 0) { Write-Output "capture unreadable"; exit 2 }

python .\beacon_analyze.py .\evidence\net\capture.pcap | Set-Content .\build\candidates.txt
$run = $LASTEXITCODE

$top = Get-Content .\build\candidates.txt | Select-Object -First 1
Write-Output "top_candidate=$top"
Write-Output "analyzer_exit=$run"
if ($run -eq 2) { exit 2 }
exit $run
```

Exit-code contract: `0` full analysis with no candidate under the CV threshold, `1` candidates present or the flow table was truncated, `2` unreadable or unsupported capture.
