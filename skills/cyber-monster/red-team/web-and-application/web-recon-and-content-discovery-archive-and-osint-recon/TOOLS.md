# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`web-recon-and-content-discovery-archive-and-osint-recon`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `waybackurls` | `waybackurls target.example > historical.txt` | Harvest archived URLs for the domain into historical.txt, then unique-sort that file as the passive coverage set | Linux, Windows, macOS |
| `gau` | `gau --subs target.example > gau-raw.txt` | Pull URLs from multiple archive and index sources into gau-raw.txt, then deduplicate near-identical captures | Linux, Windows, macOS |
| `trufflehog` | `trufflehog github --repo https://github.com/org/repo --only-verified` | Scan public repositories for secrets tied to the target and report only those that still verify | Cross-platform |
| `curl` | `curl -sS 'http://web.archive.org/cdx/search/cdx?url=target.example/*&output=text&fl=original&collapse=urlkey'` | Query the Wayback CDX index directly for the list of historically captured paths | Cross-platform |

## Minimal Script Shape

An archive-versus-live differ: it pulls a sample of historically captured URLs from the Wayback CDX index and reports which still return 200 on the live site.

```python
import urllib.request
import urllib.error

CDX = ('http://web.archive.org/cdx/search/cdx?'
       'url=target.example/*&output=text&fl=original&collapse=urlkey&limit=50')

def live_status(url):
    req = urllib.request.Request(url, method='HEAD',
                                 headers={'User-Agent': 'authorised-assessment'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None

with urllib.request.urlopen(CDX, timeout=20) as resp:
    historical = resp.read().decode('utf-8', 'replace').split()

still_live = [u for u in historical if live_status(u) == 200]
print({'historical_count': len(historical),
       'still_live_count': len(still_live),
       'sample': still_live[:5]})
```
