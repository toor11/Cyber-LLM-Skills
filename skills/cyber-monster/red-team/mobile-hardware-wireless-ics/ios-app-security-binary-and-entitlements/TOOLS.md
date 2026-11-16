# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ios-app-security-binary-and-entitlements`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `codesign` | `codesign -d --entitlements :- App.app` | The authoritative entitlement set of the built variant | macOS |
| `otool` | `otool -l App.app/App` | Whether the binary is encrypted | macOS |
| `security` | `security cms -D -i embedded.mobileprovision` | Profile type, expiry, and provisioned devices | macOS |
| `nm` | `nm -gU App.app/App` | Exported symbols, including debug and attach hooks | macOS |
| `jtool2` | `jtool2 --ent App.app/App` | Entitlements and code-signing blob in one pass | macOS |

## Minimal script shape

```python
# Classify an app bundle's entitlement risk.
import re
import subprocess

def ents(app: str) -> str:
    return subprocess.run(["codesign", "-d", "--entitlements", ":-", app],
                          capture_output=True, text=True).stderr

def cryptid(binary: str) -> int:
    out = subprocess.run(["otool", "-l", binary], capture_output=True, text=True).stdout
    m = re.search(r"cryptid\s+(\d+)", out)
    return int(m.group(1)) if m else -1

def risk(app: str, binary: str) -> dict:
    e = ents(app)
    groups = re.findall(r'"([^"]+)"', e.split("keychain-access-groups")[-1]) if "keychain-access-groups" in e else []
    return {"get_task_allow": "get-task-allow" in e and "true" in e.split("get-task-allow")[1][:20],
            "keychain_groups": groups,
            "aps_dev": "aps-environment = development" in e,
            "cryptid": cryptid(binary)}

if __name__ == "__main__":
    print(risk("Payload/App.app", "Payload/App.app/App"))
```

`get_task_allow: True` or `cryptid: 0` on a distribution build is the finding; `keychain_groups` beyond the app's own identifier names the second.
