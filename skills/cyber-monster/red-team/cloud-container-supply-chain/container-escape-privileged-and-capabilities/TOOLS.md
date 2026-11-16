# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`container-escape-privileged-and-capabilities`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `capsh` | `capsh --print` | Effective, permitted, and bounding sets inside the container | libcap |
| `getcap` | `getcap -r / 2>/dev/null` | File capabilities carried by the image's binaries | libcap |
| `awk` | `awk '/CapEff/;/CapBnd/' /proc/self/status` | The same sets without libcap, as hex masks | any Linux |
| `kubectl` | `kubectl get pods -A -o json` | Declared capability additions per workload | kubectl |
| `amicontained` | `amicontained` | Capability and namespace summary in one output | Go binary |

## Minimal script shape

```python
# Decode CapEff and rank the boundary-crossing capabilities that are present.
CAP_BITS = {
    "cap_sys_admin": 21, "cap_sys_module": 16, "cap_sys_rawio": 17,
    "cap_dac_read_search": 2, "cap_dac_override": 1, "cap_sys_ptrace": 19,
    "cap_net_admin": 12, "cap_sys_boot": 22,
}

def decode(capeff_hex: str) -> list[str]:
    val = int(capeff_hex, 16)
    return [name for name, bit in CAP_BITS.items() if val & (1 << bit)]

def report() -> dict:
    mask = ""
    for line in open("/proc/self/status"):
        if line.startswith("CapEff:"):
            mask = line.split()[1]
    return {"capeff": mask, "dangerous": decode(mask)}

if __name__ == "__main__":
    print(report())
```

A non-empty `dangerous` list is the finding, and each name is the capability the report cites with the operation it enables.
