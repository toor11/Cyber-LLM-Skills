# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`tls-and-pki-attacks-configuration-weaknesses`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `nmap` | `nmap --script ssl-enum-ciphers -p 443 host` | Complete accepted-suite inventory, grouped by protocol | nmap |
| `openssl` | `openssl s_client -connect host:443 -tls1 </dev/null` | Whether a specific legacy protocol is still accepted | OpenSSL 3.x |
| `testssl` | `testssl.sh --quiet --protocols --ciphers host:443` | Protocol and cipher findings with severity, plus renegotiation and compression | POSIX |
| `sslyze` | `sslyze --regular host:443` | Structured JSON for an estate sweep | Python |
| `rg` | `rg -n -e 'ssl_protocols' -e 'ssl_ciphers' -e 'ssl_ecdh_curve'` | The config lines that decide the surface | any |

## Minimal script shape

```python
# Weakest accepted tuple per endpoint, as a table you can attach to a finding.
import re
import subprocess

PROTOCOLS = (("-tls1", "TLSv1.0"), ("-tls1_1", "TLSv1.1"),
             ("-tls1_2", "TLSv1.2"), ("-tls1_3", "TLSv1.3"))

def probe(host: str) -> dict:
    out = {}
    for flag, label in PROTOCOLS:
        p = subprocess.run(["openssl", "s_client", "-connect", f"{host}:443",
                            "-servername", host, flag],
                           input="", capture_output=True, text=True)
        text = p.stdout + p.stderr
        suite = re.search(r"Cipher\s*:\s*(\S+)", text)
        ok = "Protocol" in text and suite is not None
        out[label] = suite.group(1) if ok else None
    return {"host": host, "protocols": out}

if __name__ == "__main__":
    print(probe("example.com"))
```

Any non-`None` value for `TLSv1.0` or `TLSv1.1` is the protocol finding; the suite strings give the cipher finding in the same output.
