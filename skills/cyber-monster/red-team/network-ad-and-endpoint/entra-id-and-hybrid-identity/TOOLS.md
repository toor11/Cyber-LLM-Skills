# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`entra-id-and-hybrid-identity`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Get-MgDomain` | `Get-MgDomain &#124; Select-Object Id,AuthenticationType` | Authentication method per domain | Cross-platform |
| `Get-MgServicePrincipal` | `Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Entra Connect Sync'"` | Sync app credentials and roles | Cross-platform |
| `roadtx` | `roadtx devicecode -c <client-id>` | Device-code flow, authorised lab only | Cross-platform |
| `Get-ADComputer` | `Get-ADComputer PAW01 -Properties userCertificate` | Device certificate presence | Windows |
| `Get-Acl` | `Get-Acl 'AD:CN=PAW01,...'` | Write ACL on the device object | Windows |

## Minimal Lab Validation Script

Report the authentication method, the sync principal's role and credential, and the device-attribute ACL.

```python
import subprocess

def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()

print("domains", ps("Get-MgDomain | Select-Object Id,AuthenticationType | ConvertTo-Json -Compress")[:300])
print("sync_app_keys", ps("(Get-MgServicePrincipal -Filter \"displayName eq 'Microsoft Entra Connect Sync'\")."
                          "KeyCredentials | Measure-Object).Count"))
print("device_cert_present", ps("(Get-ADComputer PAW01 -Properties userCertificate).userCertificate -ne $null"))
```

## Flag Notes

- `AuthenticationType` distinguishes federated from managed domains, which decides the trust anchor.
- Counting `KeyCredentials` shows how many certificates are bound, and any unexpected one is a finding.
- `userCertificate` non-null proves the device can authenticate to the tenant by certificate.
