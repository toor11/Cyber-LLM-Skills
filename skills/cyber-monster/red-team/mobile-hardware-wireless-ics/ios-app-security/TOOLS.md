# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ios-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `plutil` | `plutil -p Info.plist` | URL schemes and document types without a plist editor | macOS |
| `codesign` | `codesign -d --entitlements :- App.app` | The shipped entitlements, including associated domains and debugging flags | macOS |
| `security` | `security dump-keychain` | Keychain items and their accessibility attributes | macOS |
| `xcrun simctl` | `xcrun simctl openurl booted "scheme://..."` | Whether a scheme reaches the handler, in a simulator | Xcode |
| `otool` | `otool -L App.app/App` | Linked frameworks, which shows whether attestation or pinning libraries are present | macOS |

## Minimal script shape

```python
# Report schemes, entitlements, and storage sites from a decoded bundle.
import plistlib
import pathlib
import subprocess

def schemes(plist: str) -> list[str]:
    with open(plist, "rb") as fh:
        data = plistlib.load(fh)
    return [s for t in data.get("CFBundleURLTypes", []) for s in t.get("CFBundleURLSchemes", [])]

def entitlements(app: str) -> str:
    return subprocess.run(["codesign", "-d", "--entitlements", ":-", app],
                          capture_output=True, text=True).stderr

def report(app: str) -> dict:
    plist = f"{app}/Info.plist"
    ent = entitlements(app)
    return {"schemes": schemes(plist),
            "universal_links": "applinks:" in ent,
            "debug_entitlement": "get-task-allow" in ent,
            "broad_keychain_group": "keychain-access-groups" in ent}

if __name__ == "__main__":
    print(report("Payload/App.app"))
```

`debug_entitlement: True` on a distribution build is a finding on its own; a scheme without `universal_links` for the same action is the authority finding.
