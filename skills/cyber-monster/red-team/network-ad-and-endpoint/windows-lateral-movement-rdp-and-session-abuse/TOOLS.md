# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-lateral-movement-rdp-and-session-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nmap` | `nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info 10.20.30.20` | Negotiation reply and NLA state | Cross-platform |
| `xfreerdp` | `xfreerdp /v:10.20.30.20 /u:user /cert:ignore +auth-only` | Prove NLA negotiation with a client | Linux / macOS |
| `query session` | `query session /server:10.20.30.20` | Session inventory | Windows |
| `mstsc` | `mstsc /v:10.20.30.20 /shadow:<sessionid> /control` | Shadowing a session where policy allows | Windows |
| `tscon` | `tscon <sessionid> /dest:<target>` | Session move, requires SYSTEM | Windows |

## Minimal Lab Validation Script

Read the negotiation and policy state; establishing a session is a separate authorised step.

```python
import socket

def rdp_negotiate(host, port=3389, timeout=4):
    # X.224 connection request with RDP negotiation; the reply names the selected protocol
    req = bytes.fromhex("030000130ee000000000000100080003000000")
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(req)
        reply = s.recv(64)
    return reply.hex()

print("rdp_reply", rdp_negotiate("10.20.30.20"))
```

## Flag Notes

- `+auth-only` negotiates authentication without opening a desktop, which is the least invasive check.
- `rdp-enum-encryption` reports the selected protocol, which is the NLA evidence.
- `/control` shadowing requires the target's policy to permit it and is visible to the user unless the policy hides it.
