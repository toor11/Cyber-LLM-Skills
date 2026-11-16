# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`mobile-instrumentation-and-pinning-bypass`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `rg` | `rg -n -e 'CertificatePinner' -e 'pin-set' -e 'didReceive challenge'` | Where pinning is implemented and by which mechanism | any |
| `mitmproxy` | `mitmproxy -p 8080` with a user CA | Whether app traffic is interceptable, in a lab only | mitmproxy |
| `apktool` | `apktool d app.apk` then rebuild | Whether a code-level check is removable, by reading the code | apktool |
| `frida` | `frida -U -f PKG --codeshare` hooks | Whether a check is bypassable at runtime, on a lab device | frida |
| `curl` | `curl --proxy http://127.0.0.1:8080 https://host` | The transport-level baseline against the proxy | any |

## Minimal script shape

```python
# Classify pinning and integrity mechanisms from a source tree.
import pathlib
import re

ENFORCED = {
    "android_config": re.compile(r"<pin-set"),
    "okhttp_pinner": re.compile(r"CertificatePinner\.Builder"),
    "ios_trust_eval": re.compile(r"didReceive\s+challenge"),
}
REMOVABLE = {
    "string_compare": re.compile(r"(subject|publicKey)[\s\S]{0,80}(==|!=)[\s\S]{0,40}(expected|sha256)"),
    "client_root_check": re.compile(r"isRooted|jailbroken"),
    "client_boolean_gate": re.compile(r"if\s*\(\s*!\s*rooted\s*\)"),
}

def classify(root: str) -> dict:
    out = {"enforced": [], "removable": []}
    for p in pathlib.Path(root).rglob("*"):
        if p.suffix not in (".kt", ".swift", ".xml", ".java"):
            continue
        text = p.read_text(errors="ignore")
        for name, pat in ENFORCED.items():
            if pat.search(text):
                out["enforced"].append(f"{p}:{name}")
        for name, pat in REMOVABLE.items():
            if pat.search(text):
                out["removable"].append(f"{p}:{name}")
    return out

if __name__ == "__main__":
    print(classify("app/src"))
```

Anything in `removable` is a signal rather than a control; the report says what interception yields, not that bypass is possible.
