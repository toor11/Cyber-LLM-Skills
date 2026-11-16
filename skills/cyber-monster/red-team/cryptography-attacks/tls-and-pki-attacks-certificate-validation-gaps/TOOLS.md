# Tools, Flags, and Minimal Script Shape

> Sub-skill: [`tls-and-pki-attacks-certificate-validation-gaps`](SKILL.md) | Family: **Cryptography Attacks**

Flags below are the ones this technique actually needs. Verify with `--help` when the
installed version differs; never guess a flag into a report.

| Tool | Command | What it settles | Platform |
|---|---|---|---|
| `openssl` | `openssl s_server -accept 8443 -cert c.pem -key k.pem -www` | A test endpoint presenting a specific certificate | OpenSSL 3.x |
| `openssl` | `openssl x509 -in c.pem -noout -pubkey` | The SPKI pin value, which is what a correct pin compares | OpenSSL 3.x |
| `python` | `python -c "import ssl;print(ssl.create_default_context().verify_mode)"` | Default verification mode before any override | CPython 3.8+ |
| `rg` | `rg -n -e 'InsecureSkipVerify' -e 'verify=False'` | Disabled-verification sites | any |
| `apksigner`/`codesign` | `codesign -dvvv App.app` | Whether a pin is enforced in the shipped binary as well as the source | platform tooling |

## Minimal script shape

```python
# Verify which checks a client context actually performs, without touching prod.
import socket
import ssl

CHECKS = {
    "wrong_name": ("127.0.0.1", 8443, "api.example.com"),
    "expired": ("127.0.0.1", 8444, "api.example.com"),
    "unknown_root": ("127.0.0.1", 8445, "api.example.com"),
}

def accepts(host: str, port: int, name: str, cafile: str = "lab-ca.pem") -> str:
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=name):
                return "ACCEPTED"
    except ssl.SSLCertVerificationError as e:
        return f"rejected: {e.verify_message}"

if __name__ == "__main__":
    for label, (h, p, n) in CHECKS.items():
        print(label, accepts(h, p, n))
```

Every probe must print `rejected`; any `ACCEPTED` names the check that is missing.
