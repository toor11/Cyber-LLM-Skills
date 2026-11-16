# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-recon-and-content-discovery-directory-and-file`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ffuf` | `ffuf -u https://target.example/FUZZ -w list.txt -mc all -ac -of json -o out.json` | Autocalibration (-ac) learns the soft-404 baseline so hits are reported by divergence, not raw status | Cross-platform |
| `feroxbuster` | `feroxbuster -u https://target.example -w list.txt --rate-limit 20 --filter-status 404` | Recursive discovery with a request-rate cap to stay inside authorised load | Linux, macOS, Windows |
| `gobuster` | `gobuster dir -u https://target.example -w list.txt -x bak,old,zip,git -s 200,301,302 -b ''` | Extension fuzzing against base names with an explicit status allowlist | Cross-platform |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download} %{time_total}\n' https://target.example/path` | Capture the status, length, and timing triple that defines the differential baseline | Cross-platform |

## Minimal Script Shape

A baseline-versus-candidate checker: it records the length of two guaranteed-missing paths, then flags a candidate only when its length leaves that soft-404 band.

```python
import urllib.request

BASE = "https://target.example"
MISSING = ["/baseline-missing-9f3a", "/baseline-missing-7b2c"]
CANDIDATES = ["/.git/config", "/config.php.bak", "/backup.zip"]


def length(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, len(exc.read() or b"")


floor = [length(p) for p in MISSING]
band = max(abs(floor[0][1] - floor[1][1]), 48)
for path in CANDIDATES:
    status, size = length(path)
    diverges = abs(size - floor[0][1]) > band or status not in (floor[0][0], floor[1][0])
    print({"path": path, "status": status, "size": size, "hit": diverges})
```
