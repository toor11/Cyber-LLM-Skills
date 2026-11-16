# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`android-app-security-static-analysis`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `aapt2` | `aapt2 dump badging app.apk` | Package, version, SDK levels, and declared features | Android SDK |
| `jadx` | `jadx -d out/ --no-res app.apk` | Java-like source from the dex | jadx |
| `apktool` | `apktool d -f app.apk -o out/` | Decoded manifest, resources, and smali | apktool |
| `unzip` | `unzip -l app.apk` | Artefact inventory including native libraries | any |
| `readelf` | `readelf -sW lib/arm64-v8a/libnative.so` | Exported JNI symbols, which mark the native entry points | binutils |
| `mobsf` | `mobsf --scan app.apk` | Automated first pass across manifest, strings, and libraries | MobSF |

## Minimal script shape

```python
# Build a located inventory: artefact, class, and the string or symbol found.
import pathlib
import re
import subprocess

def dex_strings(apk: str, out: str) -> list[str]:
    subprocess.run(["jadx", "-d", out, "--no-res", apk], capture_output=True)
    return [str(p) for p in pathlib.Path(out).rglob("*.java")]

def located(files: list[str], pattern: str) -> list[dict]:
    rx = re.compile(pattern, re.I)
    hits = []
    for f in files:
        for i, line in enumerate(pathlib.Path(f).read_text(errors="ignore").splitlines(), 1):
            if rx.search(line):
                hits.append({"file": f, "line": i, "text": line.strip()[:80]})
    return hits

if __name__ == "__main__":
    files = dex_strings("app-release.apk", "/tmp/jadx")
    print({"java_files": len(files), "candidates": located(files, r"api_key|secret|bearer")[:5]})
```

Every candidate carries a file and a line, which is the locator the report needs; a candidate with no call site nearby stays a note.
