# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`websocket-security`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `websocat` | `websocat -H 'Origin: https://wssocket-attacker.example' wss://target.example/ws` | Attempt the handshake with a foreign Origin to see whether it still upgrades | Linux, macOS, Windows |
| `curl` | `curl -sS -i -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Origin: https://wssocket-attacker.example' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' https://target.example/ws` | Inspect the raw handshake response code for a cross-origin request | Cross-platform |
| `Burp Suite` | `Use the WebSockets history and 'Send' with an edited Origin header` | Replay the captured handshake with a modified Origin inside an intercepting proxy | Cross-platform |

## Minimal Script Shape

A handshake-differential harness: it sends the Upgrade from a same-origin and a foreign Origin and reports the Origin check as missing when both reach 101.

```python
import http.client
import ssl

HOST = "target.example"
PATH = "/ws"
HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
}


def handshake(origin):
    conn = http.client.HTTPSConnection(HOST, 443, context=ssl.create_default_context(), timeout=10)
    headers = dict(HEADERS, Origin=origin)
    conn.request("GET", PATH, headers=headers)
    status = conn.getresponse().status
    conn.close()
    return status


same = handshake("https://" + HOST)
foreign = handshake("https://wssocket-attacker.example")
print({"same_origin": same, "foreign_origin": foreign,
       "origin_check_missing": same == 101 and foreign == 101})
```
