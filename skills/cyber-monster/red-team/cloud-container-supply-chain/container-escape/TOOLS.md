# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`container-escape`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `capsh` | `capsh --print` | The effective and bounding capability sets inside the container | libcap |
| `readlink` | `readlink /proc/self/ns/pid /proc/self/ns/net` | Namespace inode comparison, the definitive sharing proof | Linux |
| `runc` | `runc --version` | Whether the runtime predates the masked-path fixes | any |
| `kubectl` | `kubectl get pod P -o jsonpath='{.spec.containers[*].securityContext}'` | The declared security context | kubectl |
| `amicontained` | `amicontained` | Container runtime, capabilities, and namespace summary in one output | Go binary |

## Minimal script shape

```python
# Score a container's exposure across the five control surfaces.
import json
import subprocess
from dataclasses import dataclass

@dataclass
class Surface:
    name: str
    open: bool
    evidence: str

def inside() -> list[Surface]:
    caps = subprocess.run(["capsh", "--print"], capture_output=True, text=True).stdout
    ns = subprocess.run(["readlink", "/proc/self/ns/pid", "/proc/self/ns/net"],
                        capture_output=True, text=True).stdout.split()
    host = subprocess.run(["readlink", "/proc/1/ns/pid", "/proc/1/ns/net"],
                          capture_output=True, text=True).stdout.split()
    return [
        Surface("cap_sys_admin", "cap_sys_admin" in caps.lower(), "capsh output"),
        Surface("privileged_set", "a80425fb" in caps, "CapEff pattern"),
        Surface("shared_pid_ns", len(ns) == 2 and len(host) == 2 and ns[0] == host[0], "pid inode"),
        Surface("shared_net_ns", len(ns) == 2 and len(host) == 2 and ns[1] == host[1], "net inode"),
    ]

if __name__ == "__main__":
    for s in inside():
        if s.open:
            print("OPEN", s.name, s.evidence)
```

Each `OPEN` line is a finding with the field that proves it; an empty output plus a documented absence of host mounts and a current runtime is the negative result.
