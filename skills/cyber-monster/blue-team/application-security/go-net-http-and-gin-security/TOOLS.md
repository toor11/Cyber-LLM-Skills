# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`go-net-http-and-gin-security`](SKILL.md) | Family: **Application Security**

Verified entry points for this technique. Flags below are the ones this workflow actually uses; check `--help` when the installed major version differs.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `govulncheck` | `govulncheck -show verbose ./...` | Reachability-aware advisory check against the build's actual call graph | Go |
| `gosec` | `gosec -fmt=json -out gosec.json ./...` | Timeout, path, and TLS configuration patterns | Go |
| `go` | `go version` and `go list -m -u all` | Toolchain and module currency | Go |
| `curl` | `curl -sS --limit-rate 1 -m 30 http://staging/health` | Slow-header behaviour against a staging listener | Cross-platform |

## Minimal Script Shape

The smallest shape that produces reviewable output. Adapt paths and identifiers; keep the parse-verify-print order.

```go
package main

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "time"
)

func guardedClient() *http.Client {
    dialer := &net.Dialer{Timeout: 3 * time.Second}
    return &http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                host, _, err := net.SplitHostPort(addr)
                if err != nil {
                    return nil, err
                }
                ip := net.ParseIP(host)
                if ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()) {
                    return nil, fmt.Errorf("destination not allowed: %s", host)
                }
                return dialer.DialContext(ctx, network, addr)
            },
        },
        CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
    }
}

var srv = &http.Server{
    Addr:              ":8443",
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      15 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    1 << 15,
}
```

## Verification

- The dial guard rejects the link-local metadata address and accepts an allowlisted host; both cases are printed by the probe.
- A slow-header connection is closed after `ReadHeaderTimeout`, observable in the server log.
- `govulncheck` reports no reachable stdlib advisories at the recorded toolchain version.
