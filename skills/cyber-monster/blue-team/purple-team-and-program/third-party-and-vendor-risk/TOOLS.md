# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`third-party-and-vendor-risk`](SKILL.md) | Family: **Purple Team and Program**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `idp` admin API | list OAuth grants per application with scopes | Observed versus required scopes | Cross-platform |
| `aws ec2`/flow logs | `aws ec2 describe-flow-logs` then query vendor egress | Network path verification | AWS |
| `curl` | fetch the vendor's trust centre attestation metadata | Report period and issue date | Cross-platform |
| `jq` | `jq '.vendors' register.json` | Enumerate vendors for the review cycle | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```python
import json

reg = json.load(open("vendor-register.json"))
problems = []
for v in reg["vendors"]:
    if v["tier"] == "highest" and not v.get("observed_access"):
        problems.append((v["name"], "highest tier without observed access evidence"))
    granted = set(v.get("granted_scopes", []))
    needed = set(v.get("required_scopes", []))
    unused = granted - needed
    if unused:
        problems.append((v["name"], f"unused scopes: {sorted(unused)}"))
    if v.get("attestation", {}).get("period_end", "") < "2026-06-30":
        problems.append((v["name"], "attestation period older than 12 months"))
    if not v.get("contract", {}).get("notification_hours"):
        problems.append((v["name"], "no breach notification clause"))

print("vendors:", len(reg["vendors"]), "problems:", len(problems))
for p in problems[:10]:
    print(" ", p)
```

## Verification

- Unused scopes are computed as a set difference, so over-permission is visible per vendor.
- An old attestation period is flagged even when a certification flag is set, which catches the yes/no metadata problem.
- Highest-tier vendors without observed evidence fail, forcing the technical check.
