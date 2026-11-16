# Detection Queries and Telemetry Artifacts

> Sub-skill: [`go-net-http-and-gin-security`](SKILL.md) | Family: **Application Security**

Go server and handler checks. Each row is answerable from the constructor and the handler source.

## Server Configuration

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Timeouts | `http.Server` literal fields | All four timeouts set to non-zero values |
| Header bound | `MaxHeaderBytes` | Explicit, at or below the proxy's limit |
| TLS config | `tls.Config` on the listener | `MinVersion` at TLS 1.2 or above, no `InsecureSkipVerify` |

## Request Limits

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Body bound | handlers calling `json.NewDecoder(r.Body)` | Wrapped in `http.MaxBytesReader` |
| Decoder strictness | `DisallowUnknownFields` on decoders | Enabled on write endpoints |
| Multipart bound | `r.ParseMultipartForm(n)` | Explicit memory limit |

## Outbound and Filesystem

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Dial guard | `http.Transport.DialContext` control function | Refuses loopback, link-local, and RFC1918 unless explicitly allowed |
| Redirect policy | `CheckRedirect` on the client | Bounded hops, scheme restricted |
| File root | `os.Root` or a resolved prefix check | Present on any caller-influenced path |

## Telemetry Prerequisites

- The `go.mod` version and the host toolchain, since several fixes are stdlib-level.
- A staging instance for the slow-header and oversize-body probes.
- The outbound allowlist, so the dial guard can be checked against intent.

## Deployment Gates

- The server constructor is reviewed as security-relevant configuration, not boilerplate.
- Stdlib patch level is verified at build; `govulncheck` runs in CI with the toolchain version recorded.
