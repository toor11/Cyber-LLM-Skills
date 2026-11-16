# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ics-ot-protocol-attacks`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `opcua` | `python -c "from opcua import Client; c=Client(url); c.connect(); print(c.get_endpoints())"` | The offered policies, modes, and token types | Python |
| `nmap` | `nmap --script opcua-info,modbus-discover TARGET` | Protocol presence and basic identifiers | nmap |
| `tshark` | `tshark -r cap.pcapng -Y "opcua` | Passive protocol view from a capture | Wireshark CLI |
| `zeek` | `zeek -r cap.pcapng` with the modbus and dnp3 scripts | Protocol logs for an inventory | Zeek |
| `plcscan`/`s7scan` | `python s7scan.py --host TARGET` | S7 device presence and basic identity, read-only | Python |

## Minimal script shape

```python
# Classify an OPC UA endpoint set into finding or control, per endpoint.
from dataclasses import dataclass

CURRENT = {"Basic256Sha256", "Aes256_Sha256_RsaPss", "Aes128_Sha256_RsaOaep"}
DEPRECATED = {"Basic128Rsa15", "Basic256", "None"}

@dataclass
class Endpoint:
    url: str
    policy: str
    mode: str
    tokens: list[str]

def classify(eps: list[Endpoint]) -> list[dict]:
    out = []
    for e in eps:
        short = e.policy.split("#")[-1]
        out.append({"url": e.url, "policy": short,
                    "deprecated_policy": short in DEPRECATED,
                    "anonymous": "Anonymous" in e.tokens,
                    "unencrypted": e.mode == "None"})
    return out

if __name__ == "__main__":
    print(classify([Endpoint("opc.tcp://h:4840", ".../SecurityPolicy#Basic128Rsa15", "SignAndEncrypt", ["Anonymous"])]))
```

Any `deprecated_policy`, `anonymous`, or `unencrypted` true is a separate finding; an endpoint with a current policy and certificate tokens is the control.
