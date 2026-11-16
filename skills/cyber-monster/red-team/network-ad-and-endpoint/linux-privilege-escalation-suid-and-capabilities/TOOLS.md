# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-privilege-escalation-suid-and-capabilities`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `find` | `find / -xdev -perm -4000 -type f` | Setuid inventory | Linux |
| `getcap` | `getcap -r / 2>/dev/null` | Capability inventory | Linux |
| `readelf` | `readelf -d <binary> &#124; grep -i rpath` | Library search path | Linux |
| `dpkg -V` | `dpkg -V` | Package file integrity | Linux |
| `capsh` | `capsh --decode=<hex>` | Decode a capability set | Linux |

## Minimal Lab Validation Script

Pair each privileged file with the inputs it consumes, which is the only combination that constitutes a finding.

```python
import os, stat, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

suid = [p for p in run("find / -xdev -perm -4000 -type f 2>/dev/null").splitlines() if p]
unowned = []
for path in suid:
    try:
        st = os.stat(path)
    except OSError:
        continue
    if st.st_uid != 0:
        unowned.append((path, st.st_uid))

print("suid_total", len(suid), "suid_not_root_owned", unowned[:5])
print("caps", run("getcap -r / 2>/dev/null").splitlines()[:8])
for path in suid[:5]:
    rpath = run(f"readelf -d {path} 2>/dev/null | grep -iE 'rpath|runpath'").strip()
    if rpath:
        print("rpath", path, rpath)
```

## Flag Notes

- `-perm -4000` matches the setuid bit specifically; `-perm /4000` matches any of the requested bits.
- `dpkg -V` reports files whose checksum or mode differs from the package, which is the integrity evidence.
- `getcap -r /` needs read access across the tree; run it as the assessment user and note any unreadable paths.
