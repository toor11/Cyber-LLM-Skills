# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`android-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aapt2` | `aapt2 dump xmltree --file AndroidManifest.xml app.apk` | The merged manifest, authoritative over source | Android SDK |
| `aapt2` | `aapt2 dump permissions app.apk` | Declared permissions and their protection levels | Android SDK |
| `adb` | `adb shell am start -n PKG/.Activity` | Whether a component is reachable without the permission | platform-tools |
| `apktool` | `apktool d -s app.apk -o out/` | Readable manifest and resources without full decompilation | apktool |
| `jadx` | `jadx -d out/ app.apk` | Source-level view of the component's input handling | jadx |
| `mobsf` | `mobsf --scan app.apk` | Automated manifest findings as a first pass | MobSF |

## Minimal script shape

```python
# Report exported components and whether their permission is a real boundary.
import re
import subprocess

DUMP = subprocess.run(["aapt2", "dump", "xmltree", "--file", "AndroidManifest.xml", "app.apk"],
                      capture_output=True, text=True).stdout

def components(text: str) -> list[dict]:
    out, cur = [], None
    for line in text.splitlines():
        m = re.search(r"E: (activity|service|receiver|provider)", line)
        if m:
            if cur:
                out.append(cur)
            cur = {"type": m.group(1), "exported": False, "permission": ""}
            continue
        if cur is None:
            continue
        if 'android:exported' in line and "true" in line:
            cur["exported"] = True
        m = re.search(r'android:permission\S*\s*=\S*"([^"]+)"', line)
        if m:
            cur["permission"] = m.group(1)
    if cur:
        out.append(cur)
    return out

if __name__ == "__main__":
    for c in components(DUMP):
        if c["exported"] and not c["permission"]:
            print("EXPORTED WITHOUT PERMISSION", c)
```

An empty output is the negative result; each printed component is a finding whose severity depends on what the component does with its input.
