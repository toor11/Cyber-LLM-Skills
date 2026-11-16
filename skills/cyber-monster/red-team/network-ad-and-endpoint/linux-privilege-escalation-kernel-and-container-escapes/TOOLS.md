# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-privilege-escalation-kernel-and-container-escapes`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `uname` | `uname -a` | Kernel build identity | Linux |
| `capsh` | `capsh --print` | Capability sets with decoding | Linux |
| `deepce` | `deepce.sh --no-colors` | Container escape enumeration | Linux |
| `amicontained` | `amicontained` | Container runtime and capability summary | Linux |
| `dpkg` | `dpkg -l 'linux-image*'` | Kernel package version for advisory comparison | Linux |

## Minimal Lab Validation Script

Report kernel package identity and container configuration; no exploit is executed by this probe.

```python
import os, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

print("kernel", run("uname -r").strip())
print("caps", [ln for ln in open("/proc/self/status").read().splitlines()
               if ln.startswith(("CapEff", "CapBnd"))])
mounts = open("/proc/self/mountinfo").read()
print("docker_sock", "docker.sock" in mounts)
print("containerised", os.path.exists("/.dockerenv"))
print("pkg", run("dpkg -l 'linux-image*' 2>/dev/null | tail -2").strip()[:200])
```

## Flag Notes

- `--print` in capsh decodes the hex capability mask into names, which is required for a readable finding.
- `--no-colors` keeps deepce output diffable between hosts.
- `-l` with a wildcard lists installed kernel packages, which is the advisory comparison key.
