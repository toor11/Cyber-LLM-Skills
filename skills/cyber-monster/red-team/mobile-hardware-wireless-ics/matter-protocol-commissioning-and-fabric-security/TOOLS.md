# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`matter-protocol-commissioning-and-fabric-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `chip-tool` | `chip-tool accesscontrol read acl NODE ENDPOINT` | The ACL entries with privilege and auth mode | connectedhomeip |
| `chip-tool` | `chip-tool pairing open-commissioning-window NODE ...` | Window duration behaviour | connectedhomeip |
| `chip-tool` | `chip-tool basicinformation read vendor-id NODE 0` | The device's VID, which the CD check compares | connectedhomeip |
| `chip-repl` | `chip-repl` interactive session | Ad-hoc cluster reads and writes for verification | connectedhomeip |
| `ot-ctl` | `ot-ctl state` | The Thread transport state under a Matter fabric | OpenThread CLI |

## Minimal script shape

```python
# Classify a Matter configuration: attestation, ACL, and window.
import pathlib
import re

ALLOW_ALL = re.compile(r"testAllowAllAttestationVerifier")
PROD_VERIFIER = re.compile(r"prodDacVerifier|DclRoots")
GROUP_ADMIN = re.compile(r"kAdminister[\s\S]{0,120}?kGroup|kGroup[\s\S]{0,120}?kAdminister")
UNBOUNDED = re.compile(r"kNoTimeout|NoAdvertisementDuration")

def classify(root: str) -> dict:
    out = {"allow_all": [], "prod": [], "group_admin": [], "unbounded": []}
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix not in (".cpp", ".h", ".c", ".py"):
            continue
        t = p.read_text(errors="ignore")
        for name, pat in (("allow_all", ALLOW_ALL), ("prod", PROD_VERIFIER),
                          ("group_admin", GROUP_ADMIN), ("unbounded", UNBOUNDED)):
            if pat.search(t):
                out[name].append(str(p))
    return out

if __name__ == "__main__":
    print(classify("."))
```

A non-empty `allow_all` or `group_admin` is the finding; `prod` present with no `allow_all` is the control, and `unbounded` is the window finding.
