# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`secure-design-patterns`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `opa` | `opa eval -d policy/ -i request.json 'data.authz.allow'` and `opa test policy/ -v` | Test the decision as data, including the deny branch | Cross-platform |
| `istioctl` | `istioctl proxy-config cluster deploy/api -o json` | Show whether the authorisation extension has a failure-mode policy | Kubernetes |
| `conftest` | `conftest test deploy/ --policy policy/` | Gate the deployment manifest on the documented failure mode | Cross-platform |
| `grype` / `trivy` | `trivy config deploy/ --severity HIGH,CRITICAL` | Catch manifests that disable the control (permissive policy, no timeout) | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json, subprocess

def allow(payload):
    out = subprocess.run(["opa", "eval", "-d", "policy/", "-f", "json", "-I"],
                         input=json.dumps(payload), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]

base = {"user": {"id": "u1", "tenant": "a"}, "action": "read", "resource": {"tenant": "a"}}
probe = {**base, "resource": {"tenant": "b"}}
print("baseline allow:", allow(base))   # expect True
print("probe allow:", allow(probe))     # expect False
assert allow(base) is True and allow(probe) is False
```

## Verification

- The probe must return `False`; if it returns `True`, the policy is not reading the resource tenant and the design claim is false.
- `opa test policy/` passes with a case for the missing-bundle path.
- Re-running with the resource tenant removed entirely must deny rather than error into allow.
