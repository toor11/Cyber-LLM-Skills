# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-recon-and-content-discovery`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ffuf` | `ffuf -w wordlist.txt:FUZZ -u 'https://target.example/FUZZ' -mc all -ac` | Brute force paths and auto-calibrate against the soft-404 baseline before flagging hits | Linux, Windows, macOS |
| `feroxbuster` | `feroxbuster -u https://target.example -w wordlist.txt --filter-status 404 -r` | Recursively discover directories and files while filtering the absent baseline | Linux, Windows, macOS |
| `gobuster` | `gobuster vhost -u https://target.example -w vhosts.txt --append-domain` | Enumerate virtual hosts on the same IP that serve unlinked content | Linux, Windows, macOS |
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' https://target.example/wrcd-absent-a1b2` | Capture the known-absent baseline triple that calibrates every candidate | Cross-platform |

## Minimal Script Shape

A calibrated path checker: it learns the known-absent status and size set, then flags a candidate only when it diverges from that baseline.

```python
import urllib.request
import urllib.error

BASE = 'https://target.example/'

def fetch(path):
    req = urllib.request.Request(BASE + path,
                                 headers={'User-Agent': 'authorised-assessment'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, len(exc.read())

absent = [fetch('wrcd-absent-a1b2'), fetch('wrcd-absent-c3d4')]
baseline_sizes = {s for _, s in absent}
baseline_status = {c for c, _ in absent}
candidate = fetch('static/app.js.map')
is_hit = (candidate[0] not in baseline_status) or (candidate[1] not in baseline_sizes)
print({'absent_baseline': absent, 'candidate': candidate, 'discovered': is_hit})
```
