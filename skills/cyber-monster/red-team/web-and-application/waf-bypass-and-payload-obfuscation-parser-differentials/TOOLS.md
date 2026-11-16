# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`waf-bypass-and-payload-obfuscation-parser-differentials`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -F 'field=wafprobe-ct' 'https://target.example/submit'` | Send the marker as multipart/form-data to see whether the origin accepts a body type the WAF rule set does not parse | Cross-platform |
| `curl` | `curl -sS -i -H 'Content-Type: application/x-www-form-urlencoded; charset=ibm037' --data-binary @ebcdic.bin 'https://target.example/submit'` | Deliver an alternate charset so the origin transcodes bytes the edge matched as ASCII | Cross-platform |
| `Burp Suite Repeater` | `Change Content-Type between urlencoded, multipart, and JSON on the same request and compare origin versus block verdicts` | Isolate which container the WAF fails to model while the origin still parses it | Cross-platform |
| `ffuf` | `ffuf -w ctypes.txt:CT -u https://target.example/submit -X POST -H 'Content-Type: CT' -d 'field=wafprobe-ct' -mc all -ac` | Sweep content-type values to find the body format that flips the edge verdict | Linux, Windows, macOS |

## Minimal Script Shape

A container-swap harness: it posts the same marker as urlencoded and as multipart and reports whether the origin acted on the multipart field the urlencoded rule missed.

```python
import urllib.request
import urllib.error

BASE = 'https://target.example/submit'
MARKER = 'wafprobe-ct'

def post(ctype, body):
    req = urllib.request.Request(BASE, data=body.encode(), method='POST')
    req.add_header('Content-Type', ctype)
    req.add_header('User-Agent', 'authorised-assessment')
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, (MARKER in r.read().decode('utf-8', 'replace'))
    except urllib.error.HTTPError as exc:
        return exc.code, False

urlenc = post('application/x-www-form-urlencoded', 'field=' + MARKER)
multi = post('multipart/form-data; boundary=wfpd',
             '--wfpd\r\nContent-Disposition: form-data; name="field"\r\n\r\n'
             + MARKER + '\r\n--wfpd--\r\n')
print({'urlencoded': urlenc, 'multipart': multi,
       'parser_gap': (urlenc[0] >= 400 or not urlenc[1]) and multi[1]})
```
