# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`cloud-recon-and-enumeration`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws sts get-caller-identity` | Principal, account, and partition in one call | AWS CLI v2 |
| `aws` | `aws s3api get-bucket-location --bucket B` | Per-resource metadata without account-wide listing | AWS CLI v2 |
| `az` | `az account show` | Tenant and subscription scope | Azure CLI |
| `gcloud` | `gcloud projects list` | Projects visible to the credential | Cloud SDK |
| `curl` | `curl -s "https://crt.sh/?q=%25.example.com&output=json"` | Internal hostnames from certificate transparency | any |
| `amass`/`subfinder` | `subfinder -d example.com -silent` | Passive subdomain inventory | Go binary |

## Minimal script shape

```python
# Record the permission boundary as allowed/denied pairs, not a full inventory.
import subprocess

CALLS = [
    ("s3_list", ["aws", "s3", "ls"]),
    ("bucket_location", ["aws", "s3api", "get-bucket-location", "--bucket", "known-bucket"]),
    ("ec2_describe", ["aws", "ec2", "describe-instances", "--max-items", "1"]),
    ("iam_list_users", ["aws", "iam", "list-users", "--max-items", "1"]),
    ("kms_list", ["aws", "kms", "list-keys", "--limit", "1"]),
]

def probe() -> list[dict]:
    rows = []
    for name, cmd in CALLS:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        rows.append({"call": name, "ok": r.returncode == 0,
                     "error": (r.stderr.strip().split(":")[-1].strip()[:60] if r.returncode else "")})
    return rows

if __name__ == "__main__":
    for row in probe():
        print(row)
```

The `ok` column across the five calls is the boundary summary; the report quotes it instead of a long resource list.
