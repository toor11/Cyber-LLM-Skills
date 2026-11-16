# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http2-specific-attacks`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `nghttp` | `nghttp -nv https://target.example/` | Read the server SETTINGS frame including the advertised concurrent-stream limit before any probe | Linux, macOS |
| `h2load` | `h2load -n 200 -c 1 -m 50 https://target.example/` | Drive a bounded multiplexed workload to baseline backend latency within the advertised limit | Linux, macOS |
| `h2csmuggler` | `python3 h2csmuggler.py scan --url https://target.example/` | Check for an h2c upgrade path that bypasses the front end before testing stream behaviour | Linux, macOS |
| `curl` | `curl -sS -o /dev/null -w '%{http_version}\n' --http2 https://target.example/` | Confirm HTTP/2 is negotiated so the stream-concurrency model applies | Cross-platform |

## Minimal Script Shape

An HTTP/2 settings reconnaissance harness: it shells out to nghttp to read the server SETTINGS frame and extract the advertised maximum concurrent streams, printing the limit that any reset-accounting probe must be measured against.

```python
import re
import subprocess

HOST = "https://target.example/"

def max_concurrent_streams():
    out = subprocess.run(["nghttp", "-nv", HOST],
                         capture_output=True, text=True, timeout=20)
    text = out.stdout + out.stderr
    match = re.search(r"MAX_CONCURRENT_STREAMS\D+(\d+)", text)
    return int(match.group(1)) if match else None

limit = max_concurrent_streams()
if limit is None:
    print({"http2": False, "note": "no SETTINGS frame observed"})
else:
    print({"http2": True, "max_concurrent_streams": limit,
           "measure_backend_work_against": limit})
```
