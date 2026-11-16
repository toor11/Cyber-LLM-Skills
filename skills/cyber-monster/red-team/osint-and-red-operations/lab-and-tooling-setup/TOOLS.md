# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`lab-and-tooling-setup`](SKILL.md) | Family: **OSINT and Red Operations**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** a lab manifest with networks, tool versions, and snapshot identifiers, plus an isolation test that is run and recorded.
- **Validation Gate:** a failing connection attempt from the lab to a corporate address before any scenario.
- Record the hypervisor and guest versions too: kernel and network stack differences change tool behaviour.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ip` | `ip route get 10.20.0.5` | Confirm the lab has no route to production | Linux |
| `curl` | `curl -sS --max-time 3 http://10.20.0.5/` | Connection attempt that must fail from the lab | Cross-platform |
| `virt-snapshot` | `virt-snapshot create lab-base` | Snapshot before a scenario so the lab is recoverable | Linux |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import subprocess
import yaml

lab = yaml.safe_load(open("lab.yaml", encoding="utf-8"))
for net in lab["networks"]:
    print(net["name"], net["mode"])
res = subprocess.run(["curl", "-sS", "--max-time", "3", "-o", "/dev/null",
                      "-w", "%{http_code}", "http://10.20.0.5/"], capture_output=True, text=True)
print("isolation", "BREACH" if res.returncode == 0 else "ok")
```
