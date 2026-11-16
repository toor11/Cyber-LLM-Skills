# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`cloud-storage-and-metadata-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `curl` | `curl -s -o /dev/null -w '%{http_code}' URL` | Whether an object is readable without credentials | any |
| `aws` | `aws s3api get-bucket-policy --bucket B` | The policy whose statement grants or denies public read | AWS CLI v2 |
| `aws` | `aws s3api get-bucket-acl --bucket B` | The ACL layer, which the policy does not show | AWS CLI v2 |
| `az` | `az storage container show-permissions --name C --account-name A` | Public access level at the container level | Azure CLI |
| `gsutil` | `gsutil iam get gs://B` | The IAM policy including `allUsers` grants | Cloud SDK |

## Minimal script shape

```python
# Classify exposure per object class and record the access mechanism.
import subprocess
from dataclasses import dataclass

@dataclass
class Probe:
    url: str
    label: str

def code(url: str) -> str:
    r = subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "5",
                        "-w", "%{http_code}", url], capture_output=True, text=True)
    return r.stdout or "000"

def classify(probes: list[Probe]) -> list[dict]:
    out = []
    for p in probes:
        c = code(p.url)
        out.append({"label": p.label, "status": c,
                    "exposed": c == "200"})
    return out

if __name__ == "__main__":
    for row in classify([Probe("https://acme-reports.s3.eu-west-1.amazonaws.com/q1.pdf", "report")]):
        print(row)
```

`exposed: True` is the finding and the `label` tells the report which object class; `403` entries are the controls to cite alongside it.
