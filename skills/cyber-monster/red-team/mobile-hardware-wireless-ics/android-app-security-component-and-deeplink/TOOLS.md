# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`android-app-security-component-and-deeplink`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aapt2` | `aapt2 dump xmltree --file AndroidManifest.xml app.apk` | The filters and their `autoVerify` attribute | Android SDK |
| `adb` | `adb shell am start -a android.intent.action.VIEW -d URI` | Whether a deep link reaches the handler with attacker input | platform-tools |
| `curl` | `curl -s https://HOST/.well-known/assetlinks.json` | Whether the host is actually claimed by the package | any |
| `jadx` | `jadx -d out/ app.apk` | The handler code and its validation | jadx |
| `drozer` | `drozer console connect` then `run app.activity.start` | Component invocation from a separate process with a hostile intent | drozer |

## Minimal script shape

```python
# Report deeplink hosts and whether the handler validates before a sink.
import pathlib
import re

HOST = re.compile(r'android:host="([^"]+)"')
AUTO = re.compile(r'android:autoVerify="(true|false)"')
SINKS = ("startActivity(", "loadUrl(", "File(", "openFileOutput(", "rawQuery(")

def deeplinks(manifest: str) -> list[dict]:
    text = pathlib.Path(manifest).read_text(errors="ignore")
    out = []
    for block in re.split(r"<intent-filter", text)[1:]:
        host = HOST.search(block)
        if not host:
            continue
        out.append({"host": host.group(1),
                    "auto_verify": bool(AUTO.search(block) and AUTO.search(block).group(1) == "true")})
    return out

def sinks(src_dir: str) -> int:
    n = 0
    for p in pathlib.Path(src_dir).rglob("*.kt"):
        text = p.read_text(errors="ignore")
        if "getStringExtra" in text or "intent.data" in text:
            n += sum(text.count(s) for s in SINKS)
    return n

if __name__ == "__main__":
    print({"hosts": deeplinks("app/src/main/AndroidManifest.xml"), "sink_count": sinks("app/src/main/java")})
```

A host with `auto_verify: False` is the finding; the `sink_count` tells you how much code sits between external input and a dangerous operation.
