# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`aws-attacks-compute-and-metadata`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws ec2 describe-instances --query 'Reservations[].Instances[].MetadataOptions'` | Token requirement and hop limit per instance | AWS CLI v2 |
| `aws` | `aws ec2 modify-instance-metadata-options --instance-id i-... --http-tokens required --http-put-response-hop-limit 1` | The remediation, applied per instance or in the launch template | AWS CLI v2 |
| `curl` | `curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60"` | Whether v2 is available and what a v1 GET returns | any |
| `aws` | `aws lambda get-function-configuration --function-name f --query 'Environment'` | Environment-variable exposure for a function | AWS CLI v2 |
| `prowler` | `prowler aws --services ec2 --checks ec2_instance_uses_imdsv2` | Bulk IMDSv2 compliance across an account | Python |

## Minimal script shape

```python
# Classify metadata posture per instance, read-only.
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def posture() -> list[dict]:
    data = json.loads(sh("aws", "ec2", "describe-instances", "--output", "json"))
    out = []
    for res in data["Reservations"]:
        for inst in res["Instances"]:
            meta = inst.get("MetadataOptions", {})
            out.append({
                "instance": inst["InstanceId"],
                "tokens": meta.get("HttpTokens"),
                "hop": meta.get("HttpPutResponseHopLimit"),
                "v1_open": meta.get("HttpTokens") != "required",
                "container_transit": (meta.get("HttpPutResponseHopLimit") or 1) > 1,
            })
    return out

if __name__ == "__main__":
    for row in posture():
        if row["v1_open"] or row["container_transit"]:
            print(row)
```

Each printed row is a finding with the two fields that cause it; an empty output is the negative result across the account.
