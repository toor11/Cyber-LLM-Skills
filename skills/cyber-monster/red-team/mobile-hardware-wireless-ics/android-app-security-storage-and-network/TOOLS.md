# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`android-app-security-storage-and-network`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'putString\(\"(token` | Plaintext secret writes, with file and line | any |
| `aapt2` | `aapt2 dump xmltree --file res/xml/network_security_config.xml app.apk` | The shipped network config, authoritative over source | Android SDK |
| `adb` | `adb shell run-as PKG cat shared_prefs/FILE.xml` | The at-rest content on a debuggable build | platform-tools |
| `objection` | `objection -g PKG explore` then `env` | Runtime view of preference files, databases, and keychain equivalents | objection |
| `mitmproxy` | `mitmproxy -p 8080` with a user CA installed | Whether the app trusts a user CA, in a lab only | mitmproxy |

## Minimal script shape

```python
# Classify storage sites and network posture from source.
import pathlib
import re

PLAIN = re.compile(r'getSharedPreferences\([^)]*\)[\s\S]{0,120}?putString\(\s*"(token|password|secret|api_key)', re.I)
ENCRYPTED = re.compile(r"EncryptedSharedPreferences|MasterKey\.Builder")
CLEARTEXT = re.compile(r'cleartextTrafficPermitted="true"')
USER_CA = re.compile(r'<certificates\s+src="user"')

def posture(root: str) -> dict:
    plain, enc, clear, uca = [], 0, False, False
    for p in pathlib.Path(root).rglob("*.kt"):
        text = p.read_text(errors="ignore")
        if PLAIN.search(text):
            plain.append(str(p))
        enc += len(ENCRYPTED.findall(text))
    for p in pathlib.Path(root).rglob("network_security_config.xml"):
        text = p.read_text(errors="ignore")
        clear = clear or bool(CLEARTEXT.search(text))
        uca = uca or bool(USER_CA.search(text))
    return {"plaintext_secret_files": plain, "encrypted_usages": enc,
            "cleartext_allowed": clear, "user_ca_trusted": uca}

if __name__ == "__main__":
    print(posture("app/src/main"))
```

A non-empty `plaintext_secret_files`, `cleartext_allowed: True`, or `user_ca_trusted: True` is a separate finding with its own file citation.
