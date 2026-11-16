# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-privilege-escalation-sudo-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `sudo` | `sudo -ll` | Long-form rules including defaults | Linux |
| `visudo` | `visudo -c` | Syntax check after a rule change | Linux |
| `GTFOBins` | Look up the permitted binary | Documented capability per binary | Cross-platform |
| `sudo -V` | `sudo -V` | Sudo version, which decides CVE applicability | Linux |
| `journalctl` | `journalctl -t sudo` | Recorded sudo invocations | Linux |

## Minimal Lab Validation Script

Classify each permitted binary against documented capability; no escape is executed by this probe.

```python
import subprocess

DANGEROUS = {"vim", "vi", "nano", "less", "more", "man", "find", "awk", "perl",
             "python3", "python", "ruby", "node", "tar", "zip", "rsync", "dd",
             "tee", "cp", "mv", "systemctl", "env", "ftp"}

out = subprocess.run(["sudo", "-l"], capture_output=True, text=True).stdout
for line in out.splitlines():
    if "/" not in line:
        continue
    binary = line.strip().split("/")[-1].split(" ")[0]
    if binary in DANGEROUS:
        print("unrestricted-capability", line.strip())
```

## Flag Notes

- `-ll` prints the long form, which is the only view that includes `Defaults` and `env_keep`.
- `-c` parses the sudoers files without applying them, which is safe after an edit.
- `-V` reports the sudo version, which is what a CVE applicability statement needs.
