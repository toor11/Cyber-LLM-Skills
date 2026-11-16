# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-privilege-escalation-nfs-and-share-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `showmount` | `showmount -e 10.20.30.40` | Export inventory | Linux |
| `exportfs` | `exportfs -v` | Export options on the server | Linux |
| `mount` | `mount -t nfs 10.20.30.40:/srv/app /mnt/export` | Mount for an authorised test | Linux |
| `stat` | `stat -c '%U:%G %a' <file>` | Ownership and mode of a created file | Linux |
| `nfs-ls` / `nmap` | `nmap -p 111,2049 --script nfs-ls,nfs-showmount 10.20.30.40` | Export discovery without a mount | Cross-platform |

## Minimal Lab Validation Script

Report the export options and the observed ownership mapping; no setuid binary is created by this probe.

```python
import os, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

print("exports", run("showmount -e 10.20.30.40").strip()[:400])
test = "/mnt/export/ownership-test"
if os.path.isdir("/mnt/export"):
    open(test, "w").close()
    st = os.stat(test)
    print("created_uid", st.st_uid, "mode", oct(st.st_mode & 0o777))
    os.unlink(test)
else:
    print("export not mounted; options must be read on the server with exportfs -v")
```

## Flag Notes

- `-e` lists exports and the client ranges allowed, which is the scope evidence.
- `-v` on the server shows the effective options including defaults applied by the kernel.
- `-ln` prints numeric ownership, which avoids name resolution hiding a UID mismatch.
