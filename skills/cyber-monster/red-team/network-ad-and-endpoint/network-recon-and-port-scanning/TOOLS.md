# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`network-recon-and-port-scanning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap -sS -Pn -p- --min-rate 1000 --max-retries 1 -oA full-tcp 10.20.30.0/24` | Full TCP sweep with bounded retries | Linux / macOS / Windows |
| `masscan` | `masscan 10.20.30.0/24 -p0-65535 --rate 500 -oL masscan.lst` | High-rate full-range sweep | Linux / macOS |
| `naabu` | `naabu -host 10.20.30.10 -p - -rate 300 -silent` | Fast port discovery with CDN exclusion | Cross-platform |
| `Test-NetConnection` | `Test-NetConnection -ComputerName fs01 -Port 445 -InformationLevel Detailed` | Single-port reachability from Windows | Windows |
| `tcpdump` | `tcpdump -ni eth0 'tcp[tcpflags] & (tcp-syn&#124;tcp-rst&#124;tcp-ack) != 0'` | Independent confirmation of probe answers | Linux / macOS |

## Minimal Lab Validation Script

A sweep that records the answering host, the answer class, and the exact flag set, so a later report cannot drift from what the wire showed.

```python
import subprocess, xml.etree.ElementTree as ET

TARGET = "10.20.30.0/24"
ARGS = ["nmap", "-sS", "-Pn", "-p", "22,80,443,445,3389", "--reason", "-oX", "-", TARGET]
xml = subprocess.run(ARGS, capture_output=True, text=True, check=True).stdout
for host in ET.fromstring(xml).findall("host"):
    addr = host.find("address").get("addr")
    for port in host.findall("./ports/port"):
        state = port.find("state")
        print(addr, port.get("portid"), state.get("state"), state.get("reason"))
```

## Flag Notes

- `--reason` prints why nmap chose a state; without it a filtered/open judgement is unauditable.
- `--max-retries 1` keeps a rate-limited path from silently stretching a scan for hours.
- `-oA` writes greppable, XML and nmap formats so two runs can be diffed by host and port.
