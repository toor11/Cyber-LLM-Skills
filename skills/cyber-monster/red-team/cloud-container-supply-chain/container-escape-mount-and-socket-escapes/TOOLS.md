# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`container-escape-mount-and-socket-escapes`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `kubectl` | `kubectl get pod P -o jsonpath='{.spec.volumes}'` | The volume list with host paths | kubectl |
| `docker` | `docker -H unix:///var/run/docker.sock version` | Whether the mounted socket answers, which is the escape proof | Docker CLI |
| `crictl` | `crictl --runtime-endpoint unix:///run/containerd/containerd.sock version` | The same for a containerd or CRI socket | crictl |
| `findmnt` | `findmnt -R /host` | What the mount actually exposes, including nested binds | util-linux |
| `runc` | `runc --version` | Whether masked-path abuse is possible without a host mount | any |

## Minimal script shape

```python
# Classify mounts by escape class, from the pod spec only.
import json
import subprocess

SOCKETS = (".sock",)
CRITICAL = ("/", "/etc", "/var/lib/kubelet", "/proc", "/var/run", "/run")

def pods() -> list[dict]:
    out = subprocess.run(["kubectl", "get", "pods", "-A", "-o", "json"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)["items"]

def classify(path: str) -> str:
    if path.endswith(SOCKETS):
        return "runtime_socket"
    if path in CRITICAL or any(path.startswith(c + "/") for c in CRITICAL if c != "/"):
        return "host_filesystem"
    if path == "/":
        return "host_root"
    return "data"

if __name__ == "__main__":
    for p in pods():
        for v in p["spec"].get("volumes", []):
            hp = v.get("hostPath")
            if hp:
                kind = classify(hp["path"])
                if kind != "data":
                    print(f'{p["metadata"]["namespace"]}/{p["metadata"]["name"]} {kind} {hp["path"]}')
```

Each printed line names a mount and its escape class; `runtime_socket` and `host_root` are the two that need no further argument.
