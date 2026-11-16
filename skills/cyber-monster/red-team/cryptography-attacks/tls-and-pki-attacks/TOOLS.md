# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`tls-and-pki-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl s_client -connect host:443 -servername host </dev/null` | Protocol, cipher, group, and verification result in one handshake | OpenSSL 3.x |
| `openssl` | `openssl x509 -in leaf.pem -noout -dates -issuer -subject` | Validity window and chain position for the lifecycle check | OpenSSL 3.x |
| `nmap` | `nmap --script ssl-enum-ciphers -p 443 host` | Full suite inventory including legacy protocols | nmap |
| `sslyze` | `sslyze --regular host:443` | Structured summary including certificate transparency and OCSP stapling | Python |
| `testssl` | `testssl.sh --quiet --severity HIGH host:443` | Findings ranked by severity, useful for an estate sweep | POSIX |

## Minimal script shape

```python
# Record the negotiation tuple and flag values below the floor.
import re
import subprocess

FLOOR = {"TLSv1.2", "TLSv1.3"}
WEAK_SUITES = ("CBC", "RC4", "3DES", "NULL", "RSA_WITH_AES")

def handshake(host: str, flag: str = "-tls1_3") -> dict:
    p = subprocess.run(["openssl", "s_client", "-connect", f"{host}:443",
                        "-servername", host, flag],
                       input="", capture_output=True, text=True)
    out = p.stdout + p.stderr
    ver = re.search(r"Protocol\s*:\s*(\S+)", out)
    suite = re.search(r"Cipher\s*:\s*(\S+)", out)
    group = re.search(r"(?:Server Temp Key|Negotiated group)\s*:\s*(\S+)", out)
    ok = re.search(r"Verify return code:\s*(\d+)", out)
    return {"host": host, "protocol": ver.group(1) if ver else None,
            "suite": suite.group(1) if suite else None,
            "group": group.group(1) if group else None,
            "verify_code": int(ok.group(1)) if ok else None}

def assess(t: dict) -> list[str]:
    issues = []
    if t["protocol"] and t["protocol"] not in FLOOR:
        issues.append(f"protocol below floor: {t['protocol']}")
    if t["suite"] and any(w in t["suite"] for w in WEAK_SUITES):
        issues.append(f"weak suite: {t['suite']}")
    if t["verify_code"] not in (None, 0):
        issues.append(f"chain verification failed: {t['verify_code']}")
    return issues

if __name__ == "__main__":
    for h in ("example.com",):
        t = handshake(h)
        print(t, assess(t))
```

An empty `assess` list is the `Verified Safe` record; each entry names the value that violated the floor.
