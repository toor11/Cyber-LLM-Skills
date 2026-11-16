# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`dns-rebinding-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `dig` | `dig +short A zzdns.<assessor-controlled-host>` | Observe the TTL and whether the name rebinds between answers | Linux, macOS, Windows |
| `curl (--resolve)` | `curl --resolve host:port:addr http://host/healthz` | Simulate each resolution state and test Host-header acceptance without waiting on TTL | Cross-platform |
| `Rebinding harness` | `Serve a short-TTL name that flips external to internal` | Measures the client's re-resolve behaviour under a controlled flip | Cross-platform |
| `Browser DevTools` | `Watch the Network and Security panels for a re-resolve and inward connect` | Confirms a browser acted on the rebind rather than a cached address | Cross-platform |

## Minimal Script Shape

A rebinding observer: it polls a name's A records over time and reports when an external answer flips to a private or loopback address, the signal that the name can rebind inward.

```python
import ipaddress
import socket
import time

NAME = "zzdns.assessor-controlled-host.example"

def resolve(name):
    out = set()
    try:
        for info in socket.getaddrinfo(name, 80, proto=socket.IPPROTO_TCP):
            out.add(info[4][0])
    except socket.gaierror:
        pass
    return out

def is_internal(addr):
    ip = ipaddress.ip_address(addr)
    return ip.is_private or ip.is_loopback or ip.is_link_local

seen_external = False
for _ in range(5):
    answers = resolve(NAME)
    internal = [a for a in answers if is_internal(a)]
    if answers and not internal:
        seen_external = True
    if seen_external and internal:
        print({"rebind_detected": True, "internal": internal})
        break
    time.sleep(2)
else:
    print({"rebind_detected": False})
```
