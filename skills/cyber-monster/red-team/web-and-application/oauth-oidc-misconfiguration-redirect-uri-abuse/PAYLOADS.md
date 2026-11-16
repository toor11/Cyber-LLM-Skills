# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`oauth-oidc-misconfiguration-redirect-uri-abuse`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `oauth-oidc-misconfiguration-redirect-uri-abuse`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Prefix and path-append matching probe

**Expected differential:** an authorization request with an added path on the registered host still issues a code, unlike exact matching

```text
redirect_uri=https://app.example/oauth/callback/extra
redirect_uri=https://app.example/oauth/callback%2f..%2f..%2fevil
```

### Host-variant and parser-differential probe

**Expected differential:** a sibling subdomain or a URL parsed differently by server and browser receives the code, which exact origin matching rejects

```text
redirect_uri=https://login.app.example.evil.test/cb
redirect_uri=https://app.example@attacker.test/cb
redirect_uri=https://attacker.test\@app.example/cb
```

### Allowed-host open-redirector chain

**Expected differential:** an allowed host that 302s onward forwards the code to the attacker even under exact matching

```text
redirect_uri=https://app.example/go?to=https://attacker.test/
redirect_uri=https://app.example/redirect?url=//attacker.test
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
