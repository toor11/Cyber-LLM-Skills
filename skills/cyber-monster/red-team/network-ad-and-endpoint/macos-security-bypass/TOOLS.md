# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`macos-security-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `spctl` | `spctl --status` | Gatekeeper assessment state | macOS |
| `csrutil` | `csrutil status` | SIP state | macOS |
| `codesign` | `codesign -dv --verbose=4 <bundle>` | Signature and hardened runtime flags | macOS |
| `sqlite3` | `sqlite3 TCC.db 'select * from access'` | TCC grants, where readable | macOS |
| `xattr` | `xattr -l <path>` | Quarantine and provenance attributes | macOS |

## Minimal Lab Validation Script

Report the layer states and the artefacts they permit; no layer is modified by this probe.

```python
import subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

print("gatekeeper", run("spctl --status"))
print("sip", run("csrutil status"))
print("quarantine_on_download", "com.apple.quarantine" in run("xattr -l ~/Downloads 2>/dev/null"))
print("launch_agents", len(run("ls ~/Library/LaunchAgents 2>/dev/null").splitlines()))
```

## Flag Notes

- `--status` reports the global assessment state, which is the single most important Gatekeeper value.
- `-dv --verbose=4` shows the hardened runtime flag, which macOS 26 requires for TCC prompts.
- `xattr -l` reveals `com.apple.quarantine`, whose absence on a download is the delivery anomaly.
