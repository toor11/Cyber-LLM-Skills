# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`ios-app-security-storage-and-url-handling`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'UserDefaults' -e 'kSecAttrAccessible' ios/` | Store inventory with locators | any |
| `xcrun simctl` | `xcrun simctl get_app_container booted PKG data` | The container path for at-rest inspection | Xcode |
| `plutil` | `plutil -p Preferences.plist` | Whether a credential is in a plist | macOS |
| `security` | `security find-generic-password -s SERVICE -g` | Whether an item exists in the Keychain with its attributes | macOS |
| `xcrun simctl` | `xcrun simctl openurl booted "scheme://..."` | Whether a URL handler acts on external input | Xcode |

## Minimal script shape

```python
# Classify credential stores and URL handlers from source.
import pathlib
import re

WEAK_KEYCHAIN = re.compile(r"kSecAttrAccessibleAlways(?!ThisDeviceOnly)")
GOOD_KEYCHAIN = re.compile(r"kSecAttrAccessibleWhenUnlockedThisDeviceOnly")
PLIST_SECRET = re.compile(r'UserDefaults\.\w+\.set\([^)]*,\s*forKey:\s*"(token|password|secret|refresh)"')
URL_AUTHORITY = re.compile(r"open url: URL[\s\S]{0,400}?(AuthSession|session\s*=|webView\.load)")

def posture(root: str) -> dict:
    out = {"plist_secrets": [], "weak_keychain": 0, "good_keychain": 0, "url_authority": []}
    for p in pathlib.Path(root).rglob("*.swift"):
        text = p.read_text(errors="ignore")
        if PLIST_SECRET.search(text):
            out["plist_secrets"].append(str(p))
        out["weak_keychain"] += len(WEAK_KEYCHAIN.findall(text))
        out["good_keychain"] += len(GOOD_KEYCHAIN.findall(text))
        if URL_AUTHORITY.search(text):
            out["url_authority"].append(str(p))
    return out

if __name__ == "__main__":
    print(posture("ios/App"))
```

Any entry in `plist_secrets` or `url_authority`, or a non-zero `weak_keychain`, is a separate finding with its file citation.
