# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`post-quantum-cryptography-migration-and-hybrids`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `bssl` | `bssl client -connect host:443 -curves X25519MLKEM768` | Whether the server selects the hybrid group when offered | BoringSSL |
| `openssl` | `openssl s_client -connect host:443 -groups X25519MLKEM768 -tls1_3` | The same question with the more widely available client | OpenSSL 3.5+ for the group name |
| `openssl` | `openssl x509 -in c.pem -noout -text` | Signature algorithm per certificate, the other half of the inventory | OpenSSL 3.x |
| `rg` | `rg -n -e 'ssl_ecdh_curve' -e 'namedGroups' -e 'Groups' /etc` | Manual group allowlists that override library defaults | any |
| `nmap` | `nmap --script ssl-enum-ciphers -p 443 host` | Group support summary across a host range for inventory | nmap |

## Minimal script shape

```python
# Record the negotiated group per endpoint; the differential is the group name.
import re
import subprocess

def negotiated(host: str, group: str = "X25519MLKEM768") -> dict:
    out = subprocess.run(["openssl", "s_client", "-connect", f"{host}:443",
                          "-groups", group, "-tls1_3"],
                         input="", capture_output=True, text=True).stdout + \
          subprocess.run(["openssl", "s_client", "-connect", f"{host}:443",
                          "-groups", group, "-tls1_3"],
                         input="", capture_output=True, text=True).stderr
    m = re.search(r"(?:Server Temp Key|Negotiated group)[: ]+([A-Za-z0-9_-]+)", out)
    return {"host": host, "probe_group": group,
            "negotiated": m.group(1) if m else "unknown",
            "hybrid": bool(m and "MLKEM" in m.group(1).upper())}

if __name__ == "__main__":
    for h in ("example.com", "origin.internal"):
        print(negotiated(h))
```

`hybrid: False` on an internet-facing terminator that supports TLS 1.3 is the blocking-item finding; `unknown` means the probe could not complete and must not be reported as a negative.
