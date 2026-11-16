# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`jwt-oauth-and-oidc-audit-cli-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** PyJWT 2.x with `cryptography`, `httpx` for metadata; the `options={"require": [...]}` set is the part that enforces claim presence.
- **Validation Gate:** `python -c "import jwt; print(jwt.__version__)"` and one decode of a known-good token before any probe.
- PyJWT requires `algorithms=` to be passed explicitly on every decode; omitting it is a deprecation warning now and an error in newer releases.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `PyJWT` | `python -c "import jwt; print(jwt.__version__)"` | Pin the library whose claim-validation semantics you rely on | Cross-platform |
| `curl` | `curl -sS https://issuer.example/.well-known/openid-configuration` | Fetch the metadata document the checks compare against | Cross-platform |
| `jq` | `jq .issuer <(curl -sS https://issuer.example/.well-known/openid-configuration)` | Extract one field without writing a parser | Linux, macOS, Windows |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import httpx
import jwt

base = "https://issuer.example"
meta = httpx.get(base + "/.well-known/openid-configuration", timeout=10).json()
print(meta["issuer"])
print(meta.get("code_challenge_methods_supported"))
print(meta.get("id_token_signing_alg_values_supported"))

header = jwt.get_unverified_header(token)
print(header.get("alg"), header.get("kid"))
```
