# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ics-ot-protocol-attacks-protocol-exposure-assessment`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `tshark` | `tshark -r cap.pcapng -q -z endpoints,ip` | The asset inventory from existing traffic | Wireshark CLI |
| `tshark` | `tshark -r cap.pcapng -Y modbus -T fields -e modbus.func_code` | Function codes in use, which separates reads from writes | Wireshark CLI |
| `zeek` | `zeek -r cap.pcapng` with OT scripts | Protocol logs per connection pair | Zeek |
| `nmap` | `nmap -Pn -sT -p 502 --max-rate 20 --script modbus-discover SUBNET` | A narrow read-only gap fill | nmap |
| `networkminer`/`capinfos` | `capinfos cap.pcapng` | Capture window, packet count, and interface, which are the evidence's provenance | Wireshark CLI |

## Minimal script shape

```python
# Build protocol-by-zone matrix from a capture's connection pairs.
import collections
import subprocess

def pairs(pcap: str) -> list[tuple[str, str, str]]:
    out = subprocess.run(["tshark", "-r", pcap, "-T", "fields",
                          "-e", "ip.src", "-e", "ip.dst", "-e", "_ws.col.Protocol"],
                         capture_output=True, text=True).stdout
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and all(parts):
            rows.append((parts[0], parts[1], parts[2]))
    return rows

def matrix(pcap: str, zone_of) -> dict:
    m = collections.Counter()
    for src, dst, proto in pairs(pcap):
        m[(zone_of(src), zone_of(dst), proto)] += 1
    return {f"{s}->{d} {p}": n for (s, d, p), n in m.most_common()}

if __name__ == "__main__":
    print(matrix("conduit.pcapng", lambda ip: ".".join(ip.split(".")[:3])))
```

A row where the source and destination zones differ is the crossing to review against the conduit list; everything intra-zone is the baseline inventory.
