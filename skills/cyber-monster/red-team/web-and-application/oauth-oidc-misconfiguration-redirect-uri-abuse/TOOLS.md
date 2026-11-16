# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`oauth-oidc-misconfiguration-redirect-uri-abuse`](SKILL.md) | Family: **Web and Application**

Flags below are the ones this technique actually needs. Verify with `--help` on your installed version before relying on an exact spelling.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `Burp Suite Repeater` | `Edit the redirect_uri in the authorize request and resend one variant per repeat` | Test each matching bypass against the exact-match baseline in isolation | Cross-platform |
| `curl` | `curl -sS -i 'https://idp.example/authorize?response_type=code&client_id=app&redirect_uri=https://app.example/oauth/callback/extra&state=abc'` | Observe whether a path-appended redirect still yields a 302 with a code | Cross-platform |
| `ffuf` | `ffuf -w redirect-variants.txt -u 'https://idp.example/authorize?response_type=code&client_id=app&redirect_uri=FUZZ&state=abc' -mc 302` | Enumerate which redirect variants the server accepts | Cross-platform |
| `unfurl` | `unfurl format %d%p < urls.txt` | Decompose candidate URLs saved one-per-line in urls.txt to reason about parser differentials and onward redirects | Cross-platform |

## Minimal Script Shape

A redirect-matching harness: it compares the exact registered redirect against a path-appended variant and flags prefix matching if the appended request still returns a redirect carrying a code.

```python
import urllib.parse
import urllib.request

AUTHZ = "https://idp.example/authorize"
REG = "https://app.example/oauth/callback"

def authorize(redirect_uri):
    params = {"response_type": "code", "client_id": "app",
              "redirect_uri": redirect_uri, "state": "abc"}
    url = AUTHZ + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "authorised-assessment"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.headers.get("Location", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location", "")

control = authorize(REG)
appended = authorize(REG + "/extra")
print({"control": control, "appended": appended,
       "prefix_match_suspected": appended[0] in (302, 303) and "code=" in appended[1]})
```
