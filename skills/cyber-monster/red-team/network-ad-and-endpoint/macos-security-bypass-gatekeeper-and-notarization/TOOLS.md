# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`macos-security-bypass-gatekeeper-and-notarization`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `codesign` | `codesign -dv --verbose=4 <bundle>` | Authority, flags and hardened runtime | macOS |
| `spctl` | `spctl -a -vvv -t exec <bundle>` | Assessment verdict | macOS |
| `xattr` | `xattr -p com.apple.quarantine <path>` | Quarantine marker and flags | macOS |
| `mdls` | `mdls -name kMDItemWhereFroms <path>` | Download provenance | macOS |
| `stapler` | `xcrun stapler validate <bundle>` | Notarization ticket presence | macOS |

## Minimal Lab Validation Script

Report the signature, the assessment verdict and the quarantine state; no bundle is launched by this probe.

```python
import subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

path = "/Applications/Suspect.app"
print("codesign", run(f"codesign -dv --verbose=4 '{path}' 2>&1").stderr.strip().splitlines()[:6])
print("spctl", run(f"spctl -a -vvv -t exec '{path}' 2>&1").stderr.strip().splitlines()[:3])
print("quarantine", run(f"xattr -p com.apple.quarantine '{path}' 2>&1").stdout.strip() or "absent")
print("stapler", run(f"xcrun stapler validate '{path}' 2>&1").stdout.strip()[:120])
```

## Flag Notes

- `-t exec` scopes the assessment to execution, which is the relevant policy for an app bundle.
- `--verbose=4` prints the hardened runtime flag and the team identifier, both needed for a macOS 26 finding.
- `stapler validate` confirms the notarization ticket is attached rather than merely recorded.
