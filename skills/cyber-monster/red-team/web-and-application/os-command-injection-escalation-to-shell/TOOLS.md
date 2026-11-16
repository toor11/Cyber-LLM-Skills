# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`os-command-injection-escalation-to-shell`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `python` | `python interp_enum.py` | Report which interactive interpreters resolve on the host to gauge escalation feasibility | Cross-platform |
| `ss` | `ss -tunap` | Inspect existing listeners and outbound connections to understand the host's egress posture | Linux |
| `id` | `id` | Record the executing user, group, and privileges that bound a potential interactive session | Linux, macOS |

## Minimal Script Shape

A feasibility checker: it reports which interactive interpreters are present on the host so escalation potential can be judged without ever spawning a session.

```python
import shutil

# Feasibility check only: reports which interpreters exist, it does not spawn anything.
INTERPRETERS = ["bash", "sh", "python3", "perl", "socat", "nc"]

def available():
    found = {name: shutil.which(name) for name in INTERPRETERS}
    present = [n for n, p in found.items() if p]
    return found, present

found, present = available()
upgradeable = any(n in present for n in ("bash", "python3", "socat"))
print({"resolved": found, "present": present,
       "interactive_upgrade_feasible": upgradeable})
```
