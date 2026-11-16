# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`tls-and-header-compliance-scanner-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Python `ssl` with explicit `minimum_version`/`maximum_version`; `sslyze` 6.x for full enumeration; `httpx` for header capture.
- **Validation Gate:** `python -c "import ssl; print(ssl.OPENSSL_VERSION)"` then one pinned handshake and one header pair.
- OpenSSL 3.x disables TLS 1.0/1.1 at the security level by default, so a scanner using the system library can under-report support that a legacy client would negotiate.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `openssl s_client` | `openssl s_client -connect target.example:443 -tls1_2 -servername target.example` | Single-version handshake with the negotiated cipher printed | Cross-platform |
| `sslyze` | `sslyze --regular target.example` | Full protocol and cipher enumeration with a JSON output option | Cross-platform |
| `curl` | `curl -sS -D- -o /dev/null https://target.example/` | Header block capture for a baseline pair | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import socket
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.check_hostname = True
ctx.load_default_certs()

with socket.create_connection(("target.example", 443), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname="target.example") as tls:
        print(tls.version(), tls.cipher()[0], tls.getpeercert()["notAfter"])
```
