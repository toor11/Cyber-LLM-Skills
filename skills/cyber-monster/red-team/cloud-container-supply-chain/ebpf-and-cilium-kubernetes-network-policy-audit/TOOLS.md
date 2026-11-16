# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ebpf-and-cilium-kubernetes-network-policy-audit`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `kubectl` | `kubectl get networkpolicy -A -o json` | Policy set with `policyTypes` per namespace | kubectl |
| `cilium` | `cilium config get` | Datapath flags that determine coverage | Cilium CLI |
| `cilium` | `cilium status --verbose` | Version and datapath mode in one output | Cilium CLI |
| `hubble` | `hubble observe --verdict DROPPED --namespace NS` | Which flows the datapath actually dropped, which is the enforcement evidence | Cilium CLI |
| `helm` | `helm get values cilium -n kube-system` | The values that set the routing flags | Helm |

## Minimal script shape

```python
# Report direction coverage and datapath risk per cluster.
import json
import subprocess

ADVISORY_RANGES = {
    "same_node_l7_bypass": ("1.17.13", "1.18.8", "1.19.2"),
    "vlan_l7_bypass": ("1.17.15", "1.18.9"),
}

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True).stdout

def namespace_coverage() -> list[dict]:
    out = []
    for ns in sh("kubectl", "get", "ns", "-o", "jsonpath={.items[*].metadata.name}").split():
        data = json.loads(sh("kubectl", "get", "networkpolicy", "-n", ns, "-o", "json") or '{"items":[]}')
        types = set()
        for p in data.get("items", []):
            types.update(p.get("spec", {}).get("policyTypes", []))
        out.append({"namespace": ns, "ingress": "Ingress" in types, "egress": "Egress" in types})
    return out

if __name__ == "__main__":
    for row in namespace_coverage():
        if not row["egress"]:
            print("NO EGRESS POLICY", row)
```

A printed namespace has unrestricted egress; the report pairs it with the reachability probe that proves it and the policy that would close it.
