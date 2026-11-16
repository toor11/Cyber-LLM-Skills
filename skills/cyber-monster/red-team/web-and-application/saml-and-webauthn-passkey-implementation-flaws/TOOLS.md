# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`saml-and-webauthn-passkey-implementation-flaws`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sS -i -X POST 'https://login.example/webauthn/assertion' -H 'Content-Type: application/json' --data @assertion.json` | Replay a captured assertion JSON with one field altered so the server's accept or reject decision is visible | Cross-platform |
| `py_webauthn` | `python -c "import webauthn; help(webauthn.verify_authentication_response)"` | Read the expected_challenge, expected_origin, and expected_rp_id arguments that show which bindings a correct relying party enforces | Cross-platform |
| `openssl` | `openssl dgst -sha256 rp-id.txt` | Hash the RP ID saved in rp-id.txt; the digest is the expected rpIdHash for authenticatorData comparison | Linux, macOS |
| `Burp Suite Repeater` | `Send the assertion POST to Repeater and edit clientDataJSON per probe` | Keeps the baseline and a single-field probe on one connection for a clean differential | Cross-platform |

## Minimal Script Shape

A clientDataJSON inspector: it decodes the ceremony data and reports whether the type, origin, and challenge match what the relying party issued, so a suspected missing binding can be judged without a live login.

```python
import base64
import json
import sys


def b64url(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def inspect(client_data_b64, expected_origin, expected_challenge):
    client = json.loads(b64url(client_data_b64))
    return {
        "type_ok": client.get("type") == "webauthn.get",
        "origin_ok": client.get("origin") == expected_origin,
        "challenge_ok": client.get("challenge") == expected_challenge,
    }


if __name__ == "__main__":
    blob, origin, challenge = sys.argv[1], sys.argv[2], sys.argv[3]
    checks = inspect(blob, origin, challenge)
    verdict = "binds this ceremony" if all(checks.values()) else "missing a binding"
    print(checks, verdict)
```
