# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-request-smuggling-http2-desync`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -o /dev/null -w '%{http_version} %{time_total}\n' --http2 https://target.example/` | Confirm the edge negotiates HTTP/2 with the client before testing downgrade framing | Cross-platform |
| `Burp Suite Repeater` | `Switch the request to HTTP/2, disable auto content-length, and edit DATA versus the content-length header` | Send a byte-exact DATA-versus-length mismatch that higher-level clients would normalise away | Cross-platform |
| `h2csmuggler` | `python3 h2csmuggler.py scan --url https://target.example/` | Detect an h2c upgrade or downgrade path that reveals the translation layer under test | Linux, macOS |
| `nghttp` | `nghttp -nv https://target.example/` | Inspect the raw HTTP/2 frames and pseudo-headers the edge accepts before crafting a mismatch | Linux, macOS |

## Minimal Script Shape

An HTTP/2 downgrade reconnaissance harness: it shells out to curl to confirm the client side negotiates HTTP/2 and records the negotiated version and response time, printing whether a downgrade path is worth testing for H2.CL or H2.TE framing.

```python
import subprocess

HOST = "https://target.example/"

def negotiated_version():
    out = subprocess.run(
        ["curl", "-sS", "-o", "/dev/null",
         "-w", "%{http_version} %{time_total}",
         "--http2", HOST],
        capture_output=True, text=True, timeout=20)
    return out.stdout.strip()

result = negotiated_version()
parts = result.split()
version = parts[0] if parts else "?"
elapsed = parts[1] if len(parts) > 1 else "?"
is_h2 = version.startswith("2")
print({"http_version": version, "time_total": elapsed,
       "downgrade_path_worth_testing": is_h2})
```
