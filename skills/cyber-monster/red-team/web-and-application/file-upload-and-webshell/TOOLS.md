# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`file-upload-and-webshell`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -F 'file=@marker.png;type=image/png' https://target.example/upload` | Submit a benign marker with a chosen declared type to test the type decision | Cross-platform |
| `Burp Suite Repeater` | `Resend the multipart upload editing filename, Content-Type, and magic bytes one field at a time` | Isolate which single control the validator trusts | Cross-platform |
| `ffuf` | `ffuf -u https://target.example/uploads/FUZZ -w names.txt -mc 200` | Locate the stored artefact URL when the server renames uploads | Linux, macOS, Windows |
| `exiftool` | `exiftool marker.png` | Confirm the benign marker stays a valid image so the probe is non-destructive | Cross-platform |

## Minimal Script Shape

A marker-evaluation harness: it fetches an uploaded benign marker and reports whether the server returned its source bytes or evaluated output, which indicates an execution context.

```python
import sys, urllib.request

def body(url):
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", "replace")

MARKER_URL = sys.argv[1] if len(sys.argv) > 1 else "https://target.example/uploads/marker.ext"
SOURCE_TOKEN = "benign-echo UPLOAD_PROBE_7F3A"
EXPECTED_OUTPUT = "UPLOAD_PROBE_7F3A"

served = body(MARKER_URL)
evaluated = EXPECTED_OUTPUT in served and SOURCE_TOKEN not in served
print({"url": MARKER_URL,
       "source_token_present": SOURCE_TOKEN in served,
       "evaluated_output_present": EXPECTED_OUTPUT in served,
       "execution_context": evaluated})
```
