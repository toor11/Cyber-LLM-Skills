# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`http-request-smuggling`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Disable 'Update Content-Length', craft the framing by hand, and use 'Send group in sequence (single connection)'` | Hold framing exactly as typed so the parser disagreement, not Burp normalisation, is what is tested | Cross-platform |
| `smuggler.py` | `python3 smuggler.py -u https://target.example/ -q` | Run the non-destructive timing differential across CL.TE and TE.CL permutations against an authorised host | Linux, macOS, Windows |
| `curl` | `curl -sS -o /dev/null -w '%{time_total}\n' --max-time 15 https://target.example/` | Capture a baseline response-time triple so a later stall is measured against a known floor | Cross-platform |
| `h2csmuggler` | `python3 h2csmuggler.py scan --url https://target.example/` | Check for an h2c upgrade path that bypasses the front end before testing HTTP/1 framing | Linux, macOS |

## Minimal Script Shape

An ambiguous-framing acceptance checker: it opens one TLS connection and sends a benign request that carries both Content-Length and Transfer-Encoding with a terminated empty body, then reports whether the edge rejected the ambiguity (good) or accepted it (desync precondition present).

```python
import socket
import ssl

HOST = "target.example"
PORT = 443

def first_line(raw):
    ctx = ssl.create_default_context()
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as tls:
            tls.sendall(raw.encode())
            data = tls.recv(256).decode(errors="replace")
    return data.splitlines()[0] if data else "<no response>"

ambiguous = (
    "POST / HTTP/1.1\r\nHost: %s\r\n"
    "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % HOST
)
status = first_line(ambiguous)
rejected = " 400" in status or " 501" in status
print({"status_line": status,
       "verdict": "edge rejected ambiguous framing (good)" if rejected
       else "edge accepted ambiguous framing (desync precondition)"})
```
