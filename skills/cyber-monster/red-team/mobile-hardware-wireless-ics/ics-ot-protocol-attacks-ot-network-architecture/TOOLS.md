# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ics-ot-protocol-attacks-ot-network-architecture`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'permit' -e 'allow' fw-config.txt` | The conduit rules, which are the architecture's facts | any |
| `ip` | `ip -brief addr` on each host | Whether a host spans two zones | Linux |
| `traceroute` | `traceroute -n -T -p 502 10.20.30.40` | The path and the hop where the crossing happens | POSIX |
| `nmap` | `nmap -Pn -p 502,102 10.20.30.40 --reason` | Whether a port is reachable and why | nmap |
| `netstat`/`ss` | `ss -tnp` on the engineering host | Which sessions cross the boundary | Linux |

## Minimal script shape

```python
# Report crossing rules: any permit whose source spans more than one host.
import re

RULE = re.compile(r"^(permit|allow)\s+(\w+)\s+(\S+)\s+(\S+)(?:\s+eq\s+(\d+))?", re.M)

def crossings(config: str) -> list[dict]:
    out = []
    for m in RULE.finditer(config):
        src, dst, port = m.group(3), m.group(4), m.group(5)
        out.append({"action": m.group(1), "src": src, "dst": dst, "port": port,
                    "broad_source": "/" in src and not src.split("/")[1].startswith("32"),
                    "any_port": port is None})
    return out

if __name__ == "__main__":
    for r in crossings(open("fw-config.txt").read()):
        if r["broad_source"] or r["any_port"]:
            print("BROAD CONDUIT", r)
```

A `BROAD CONDUIT` entry is the finding and the rule text is the citation; narrow rules with a single host and port are the controls listed in the non-findings.
