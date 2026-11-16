# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`cloud-iam-privilege-escalation`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws iam simulate-principal-policy` | The evaluator's verdict for one principal and action | AWS CLI v2 |
| `az` | `az role assignment list --all` | Assignment graph with scopes | Azure CLI |
| `gcloud` | `gcloud projects get-iam-policy P --flatten="bindings[].members"` | Flattened grant list for filtering | Cloud SDK |
| `pmapper` | `pmapper graph create` then `pmapper query 'who can do ACTION with ARN'` | AWS graph and reverse reachability | Python |
| `Cloudsplaining` | `cloudsplaining scan --input-file iam.json` | Ranked escalation findings per policy | Python |

## Minimal script shape

```python
# Two-hop chain search over a provider-neutral edge list.
import collections
import json

def load(path: str) -> list[tuple[str, str, str]]:
    # edges: (from_principal, to_principal, primitive)
    return [tuple(row) for row in json.load(open(path))]

def paths(edges, start: str, goals: set[str], max_hops: int = 2):
    graph = collections.defaultdict(list)
    for a, b, prim in edges:
        graph[a].append((b, prim))
    found = []
    frontier = [(start, [])]
    for _ in range(max_hops):
        nxt = []
        for node, trail in frontier:
            for to, prim in graph[node]:
                step = trail + [(node, prim, to)]
                if to in goals:
                    found.append(step)
                nxt.append((to, step))
        frontier = nxt
    return found

if __name__ == "__main__":
    edges = load("edges.json")
    for p in paths(edges, "ci-runner", {"admin-role", "deploy-role"}):
        print(" -> ".join(f"{a} --{prim}--> {b}" for a, prim, b in p))
```

Each printed path is a chain with its primitives named; the report then checks whether the start principal is attacker-reachable and whether a boundary or SCP breaks the path.
