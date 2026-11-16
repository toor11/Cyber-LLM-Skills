# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`serverless-and-function-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aws` | `aws lambda get-function-url-config --function-name F` | Whether the function has a public URL and its auth type | AWS CLI v2 |
| `aws` | `aws lambda get-function-configuration --function-name F` | Role, environment keys, timeout, and concurrency in one call | AWS CLI v2 |
| `aws` | `aws iam simulate-principal-policy --policy-source-arn ROLE --action-names ACTION` | What the role can do, per action | AWS CLI v2 |
| `curl` | `curl -s -o /dev/null -w '%{http_code}' $FUNCTION_URL` | Whether unauthenticated invocation succeeds | any |
| `checkov` | `checkov -d template.yaml --framework sam` | Template-level findings for public functions and wildcard roles | Python |

## Minimal script shape

```python
# Rank functions by public reachability and role breadth.
import json
import subprocess

def sh(*a: str) -> str:
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout

def functions() -> list[dict]:
    out = []
    for f in json.loads(sh("aws", "lambda", "list-functions", "--output", "json"))["Functions"]:
        name = f["FunctionName"]
        url = json.loads(sh("aws", "lambda", "get-function-url-config",
                            "--function-name", name, "--output", "json") or "{}")
        cfg = json.loads(sh("aws", "lambda", "get-function-configuration",
                            "--function-name", name, "--output", "json"))
        out.append({
            "name": name,
            "public": url.get("AuthType") == "NONE",
            "role": cfg["Role"].rsplit("/", 1)[-1],
            "env_keys": sorted(cfg.get("Environment", {}).get("Variables", {})),
        })
    return out

if __name__ == "__main__":
    for row in functions():
        if row["public"]:
            print("PUBLIC", row)
```

Each `PUBLIC` row is a finding; the `env_keys` list is the second finding when it names credentials, and the `role` value leads to the permission review.
