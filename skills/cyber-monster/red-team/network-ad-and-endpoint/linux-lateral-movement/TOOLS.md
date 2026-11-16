# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`linux-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Entry points verified against current releases. Impacket, Certipy and netexec rename subcommands between minor versions; check `--help` before scripting.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ssh` | `ssh -o BatchMode=yes -o ConnectTimeout=3 user@host 'id'` | Non-interactive reachability proof | Cross-platform |
| `ssh-keygen` | `ssh-keygen -y -f key` | Confirm a private key is usable | Cross-platform |
| `ssh-add` | `ssh-add -l` | Keys held by the running agent | Cross-platform |
| `find` | `find /home -name authorized_keys -writable` | Writable authorisation files | Linux |
| `ansible-inventory` | `ansible-inventory --list` | Host reach from the automation inventory | Linux |

## Minimal Lab Validation Script

Report credential usability and authorisation scope; no key is copied and no `authorized_keys` file is modified.

```python
import os, subprocess

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

keys = [p for p in run("ls ~/.ssh 2>/dev/null").split() if not p.endswith(".pub")]
print("private_keys", keys)
print("agent_keys", run("ssh-add -l 2>/dev/null").strip()[:200])
print("known_hosts_count", len(run("cut -d' ' -f1 ~/.ssh/known_hosts 2>/dev/null").split()))
print("automation_secrets", run("ls ~/.aws ~/.config/gcloud 2>/dev/null").split()[:5])
```

## Flag Notes

- `BatchMode=yes` prevents an interactive password prompt, so a hang means the key was not accepted.
- `ConnectTimeout=3` keeps a probe from stalling on an unreachable host.
- `ssh-add -l` lists agent-held key fingerprints, which is the forwarded-key evidence.
