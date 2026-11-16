# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`enterprise-appliance-n-day-vpn-remote-access`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `curl` | `curl -sSk -o /dev/null -w '%{http_code} %{size_download}\n' https://gateway.example/remote/login` | Capture the pre-auth baseline status and body-size pair for the portal | Cross-platform |
| `httpx` | `httpx -u https://gateway.example -title -tech-detect -status-code` | Fingerprint the appliance title and technology to drive version mapping | Linux, macOS, Windows |
| `nuclei` | `nuclei -u https://gateway.example -tags vpn,cve,tech` | Match the firmware against known-weakness templates for that model without exploiting | Linux, macOS, Windows |
| `openssl` | `openssl s_client -connect gateway.example:443 -servername gateway.example` | Read the TLS certificate and SNI routing to confirm the appliance vendor | Cross-platform |

## Minimal Script Shape

A pre-auth reachability harness: it probes a set of appliance endpoints without a session and reports which answer, flagging an image that still needs a precise firmware pin.

```python
import sys, urllib.error, urllib.request

GATEWAY = sys.argv[1] if len(sys.argv) > 1 else "https://gateway.example"
PREAUTH_PATHS = ["/remote/login", "/sslvpn/portal/locale/en.json", "/diag/status"]

def probe(path):
    req = urllib.request.Request(GATEWAY + path, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, 0

answered = {p: probe(p) for p in PREAUTH_PATHS}
reachable = {p: s for p, (s, _) in answered.items() if s and s < 400}
print({"gateway": GATEWAY, "preauth_responses": answered,
       "reachable_without_session": reachable,
       "needs_firmware_pin": bool(reachable)})
```
