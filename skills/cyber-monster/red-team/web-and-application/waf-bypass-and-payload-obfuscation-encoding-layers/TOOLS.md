# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-bypass-and-payload-obfuscation-encoding-layers`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' --data-urlencode 'q=wafprobe-encd' 'https://target.example/search'` | Capture the status and body-size baseline for the plaintext marker so each encoding layer can be compared against it | Cross-platform |
| `ffuf` | `ffuf -w encodings.txt:ENC -u 'https://target.example/search?q=ENCwafprobe' -mc all -ac` | Sweep a list of encoding wrappers against one benign marker and auto-calibrate to show which layer changes the edge verdict | Linux, Windows, macOS |
| `Burp Suite Intruder` | `Mark the marker as a payload position, set payload processing to URL/double-URL/Unicode, run a single request set` | Apply each encoding transform to the same marker and read the origin reflection to see which layer the backend decoded | Cross-platform |
| `python unicodedata` | `python -c "import unicodedata,sys;print(unicodedata.normalize('NFKC', sys.argv[1]))" $'\uff41\uff42\uff43'` | Predict the ASCII form the origin will fold a candidate Unicode value to before sending it | Cross-platform |

## Minimal Script Shape

A decode-depth harness: it sends a benign marker plain and double-encoded and reports whether the origin reflected the same decoded marker only for the wrapped form.

```python
import urllib.parse
import urllib.request
import urllib.error

BASE = 'https://target.example/search'
MARKER = 'wafprobe-encd'

def send(raw_q):
    url = BASE + '?q=' + raw_q
    req = urllib.request.Request(url, headers={'User-Agent': 'authorised-assessment'})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, (MARKER in r.read().decode('utf-8', 'replace'))
    except urllib.error.HTTPError as exc:
        return exc.code, False

plain = send(urllib.parse.quote(MARKER))
double = send(urllib.parse.quote(urllib.parse.quote(MARKER)))
print({'plaintext': plain, 'double_encoded': double,
       'decode_gap': (not plain[1] or plain[0] >= 400) and double[1]})
```
