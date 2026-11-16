# Detection Queries and Telemetry Artifacts

> Sub-skill: [`pcap-and-netflow-beacon-analysis-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Capture analysis and statistical artifacts owned by this slug. Confirm link types and encapsulation before trusting parsed fields.

## Observable Signals

| # | Indicator / Artifact | Confidence | Proves |
|---|---|---|---|
| 1 | Coefficient of variation over inter-arrival deltas | High | Timing regularity is quantified and scale-free |
| 2 | Connection count above the sample floor | High | The statistic rests on enough observations to be meaningful |
| 3 | Mean interval inside a plausible band | High | The regularity is machine-cadence, not event-driven noise |
| 4 | DNS label-length distribution plus NXDOMAIN ratio | High | Tunneling or DGA pattern rather than merely unusual names |
| 5 | Flow-table eviction counter above zero | High | The analysis covered a truncated prefix of the capture |

## Detection Artifacts

```text
[pcap-and-netflow-beacon-analysis-scripting:rule-spec] flow key + connection-start timestamps + count/mean/stdev/CV in every row
[pcap-and-netflow-beacon-analysis-scripting:filter-fp] periodic patch, NTP, and monitoring agents score low CV legitimately
[pcap-and-netflow-beacon-analysis-scripting:correlate] a beacon candidate is corroborated by destination reputation or JA3/JA4 consistency
```

Stream a capture and print the top candidates (Windows PowerShell 5.1 invoking Python):

```powershell
python .\beacon_analyze.py .\evidence\net\capture.pcap | Set-Content .\build\beacon-candidates.txt
$run = $LASTEXITCODE
Get-Content .\build\beacon-candidates.txt | Select-Object -First 10
Write-Output "analyzer exit=$run"
```

Independent confirmation with tshark, which does not share the parser's assumptions:

```powershell
tshark -r .\evidence\net\capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields `
    -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport |
    Set-Content .\build\syns.tsv
(Get-Content .\build\syns.tsv | Measure-Object -Line).Lines
```

DNS feature extraction for tunneling checks:

```powershell
tshark -r .\evidence\net\capture.pcap -Y "dns.flags.response==0" -T fields `
    -e dns.qry.name -e dns.flags.rcode |
    Set-Content .\build\dns-queries.tsv
Get-Content .\build\dns-queries.tsv | Select-Object -First 20
```

Memory bound check: the analyzer must stay flat on a large capture.

```powershell
$before = (Get-Process -Name python -ErrorAction SilentlyContinue).WorkingSet64
python .\beacon_analyze.py .\evidence\net\large.pcap | Out-Null
$peak = (Get-Process -Name python -ErrorAction SilentlyContinue).PeakWorkingSet64
Write-Output "peak_working_set_mb=$([math]::Round($peak/1MB,1))"
```

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Baseline the environment's periodic traffic before deploying, so patch and monitoring jobs are expected rather than rediscovered each hunt.
- Report the capture window and flow-table eviction count beside every candidate list.
