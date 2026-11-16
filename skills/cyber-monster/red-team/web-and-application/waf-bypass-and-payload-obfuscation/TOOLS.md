# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-bypass-and-payload-obfuscation`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `wafw00f` | `wafw00f https://target.example/` | Fingerprint the WAF vendor so vendor-specific container behavior is known | Linux, macOS, Windows |
| `curl` | `curl -sS -i https://target.example/search -F 'q=<waf-marker>'` | Resend the payload as multipart to test container interchange against the urlencoded baseline | Cross-platform |
| `ffuf` | `ffuf -w containers.txt -u https://target.example/search -X POST -d 'q=FUZZ'` | Sweep container and encoding variants to find one the WAF passes | Linux, macOS, Windows |
| `Burp Suite Repeater` | `Use change-body-encoding to toggle urlencoded and multipart on one request` | Hold the payload constant while mutating only the container | Cross-platform |

## Minimal Script Shape

Sends the same marker value as urlencoded and as multipart to the same route and reports a suspected container bypass when the urlencoded form is blocked but the multipart form returns 200.

```python
import urllib.request

URL = "https://target.example/search"
MARKER = "waf-test-marker-xyz"

def send(body, content_type):
    req = urllib.request.Request(URL, data=body, method="POST")
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code

urlencoded = send(("q=" + MARKER).encode(), "application/x-www-form-urlencoded")
bnd = "----xyz"
multipart = ("--" + bnd + "\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n"
             + MARKER + "\r\n--" + bnd + "--\r\n").encode()
mp = send(multipart, "multipart/form-data; boundary=" + bnd)
print({"urlencoded_status": urlencoded, "multipart_status": mp,
       "container_bypass_suspected": urlencoded == 403 and mp == 200})
```
