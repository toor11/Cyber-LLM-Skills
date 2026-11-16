# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`terraform-state-and-gitops-argocd-security`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `terraform` | `terraform init -backend=false` | Reads the backend block without connecting to it | Terraform |
| `aws` | `aws s3api head-object --bucket B --key K` | Server-side encryption and KMS key of the state object, without downloading it | AWS CLI v2 |
| `aws` | `aws s3api get-bucket-versioning --bucket B` | Whether state versions are retained, which is the recovery control | AWS CLI v2 |
| `aws` | `aws dynamodb describe-table --table-name L` | Whether the lock table exists and is healthy | AWS CLI v2 |
| `kubectl` | `kubectl get appprojects -n argocd -o json` | AppProject source, destination, and cluster-resource scope | kubectl |
| `argocd` | `argocd proj get PROJECT` | The same scope in human-readable form | Argo CD CLI |

## Minimal script shape

```python
# Report state-backend controls and AppProject breadth from declarative files.
import pathlib
import re

BACKEND = re.compile(r'backend\s+"(\w+)"\s*\{(.*?)\}', re.S)
NEEDED = ("encrypt", "kms_key_id", "dynamodb_table")

def backend_report(root: str) -> list[dict]:
    out = []
    for p in pathlib.Path(root).rglob("*.tf"):
        for m in BACKEND.finditer(p.read_text(errors="ignore")):
            body = m.group(2)
            out.append({"file": str(p), "type": m.group(1),
                        "missing": [k for k in NEEDED if k not in body]})
    return out

def project_report(root: str) -> list[dict]:
    out = []
    for p in pathlib.Path(root).rglob("*appproject*.y*ml"):
        text = p.read_text(errors="ignore")
        out.append({"file": str(p),
                    "wildcard_source": '"*"' in text and "sourceRepos" in text,
                    "cluster_resources": "clusterResourceWhitelist" in text and "kind: \"*\"" in text})
    return out

if __name__ == "__main__":
    for row in backend_report(".") + project_report("."):
        print(row)
```

A non-empty `missing` list or either boolean true is the finding; the file path is the citation and the remediation is the specific key that is absent.
