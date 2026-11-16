---
name: go-net-http-and-gin-security
description: "Reviews and hardens Go `net/http`, Gin, Echo, and Chi services: `http.Server` ReadHeaderTimeout/MaxBytesReader Slowloris & OOM defenses, `html/template` vs `text/template` confusion, `sql.DB` placeholder usage, SSRF-safe custom `net.Dialer.Control` socket checks, and `filepath` root confinement (`os.Root`). Use when auditing Go web services."
family: application-security
tier: core
triggers: ["golang web security", "gin security review", "readheadertimeout go", "net.dialer.control ssrf", "os.root go"]
cwe: [CWE-400, CWE-918]
owasp: [A05:2025]
attack: []
capec: []
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Go Net Http and Gin Security - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Go's standard library is safe by construction for output (`html/template` escapes), for SQL (driver placeholders), and for paths (`os.Root` from 1.24 confines traversal) - but the server defaults are not: an `http.Server` with zero timeouts is a Slowloris target, an unbounded `r.Body` is a memory target, and an `http.Client` without a `DialContext` guard is an SSRF primitive. The review checks the server's explicit configuration and request-scoped limits, then the few places where a handler reaches past the safe default.

- **CWE-400 / CWE-918 / CWE-22:** resource exhaustion from missing limits, SSRF from unguarded clients, and traversal from resolved-but-unconfined paths.
- Go 1.26.11 and 1.27.4 (10 November 2026) carry the current stdlib fixes; CVE-2026-97054 is the MaxBytesReader header race, and the October 2026 `x/net` releases fix HTTP/2 trailer memory exhaustion (CVE-2026-78659) and HPACK encoder races (CVE-2026-97032).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the server is constructed with `http.ListenAndServe` **THEN** it has zero timeouts; replace it with an explicit `http.Server` before reviewing anything else.
2. **IF** the handler calls `http.Get` or a default client **THEN** check for a `DialContext` that refuses private addresses, since the default transport will reach the metadata endpoint.
3. **IF** the framework is Gin, Echo or Chi **THEN** check route-group middleware application, since groups registered after `Use` do not inherit it.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the server constructor.** Record `ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, and `MaxHeaderBytes`. Missing timeouts are the most common finding and the cheapest fix.
2. **Check request-scoped limits per route.** `http.MaxBytesReader` on body-consuming handlers, a decoder with `DisallowUnknownFields`, and a size bound for multipart or nested payloads.
3. **Choose the branch by outbound or filesystem reach.** Outbound HTTP takes the dial-guard branch; file serving takes `os.Root` or a resolved-prefix branch; templates take `html/template` rather than `text/template`.
4. **Define the baseline-vs-probe differential.** Baseline: a normal request with a modest body. Probes: a body exceeding the limit, a slow-header connection, and an outbound URL pointing at a link-local address. Each must produce a bounded rejection rather than growth or a successful dial.
5. **State the stop condition and the proof.** Stop when the server config is explicit, every body-consuming route is bounded, and the three probes are rejected; proof is the config struct plus the probe results.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `http.ListenAndServe(addr, mux)` with no timeouts | Proves Slowloris exposure: slow headers hold goroutines indefinitely on the standard library. |
| `r.Body` decoded without `MaxBytesReader` | Proves memory exhaustion; the decoder allocates whatever the client sends. |
| `http.Client{}` or `http.Get` reaching a caller-supplied URL | Proves SSRF on Go; the default transport dials link-local and metadata addresses. |
| `text/template` for HTML output | Proves no contextual escaping, unlike `html/template`, so a user value becomes markup. |

## Worked Contrast

**Vulnerable Go HTTP Server (Zero Timeouts + Unbounded Body + Unchecked Outbound SSRF):**

```go
func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
        body, _ := io.ReadAll(r.Body) // BUG 1: Unbounded read OOMs server on multi-GB POST
        resp, _ := http.Get(string(body)) // BUG 2: SSRF to 169.254.169.254 / RFC1918
        io.Copy(w, resp.Body)
    })
    http.ListenAndServe(":8080", mux) // BUG 3: Default Server has NO ReadHeaderTimeout (Slowloris)
}
```

**Hardened `http.Server` (Explicit Timeouts + `MaxBytesReader` + `DialContext` IP Guard):**

```go
srv := &http.Server{
    Addr: ":8080", Handler: mux,
    ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second,
}
// Inside handler: r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
// On outbound http.Transport.DialContext Control: reject netip.Addr.IsPrivate() / IsLoopback() / IsLinkLocalUnicast()
```

**Why this matters:** Never call `http.ListenAndServe` with default zero timeouts, always cap `r.Body` with `http.MaxBytesReader`, use `html/template` (not `text/template`) for HTML, and validate resolved IPs inside `Dialer.Control` to defeat DNS rebinding SSRF.

## When It Is NOT This Issue

- **`text/template` for non-HTML output.** Generating SQL, config files, or emails with `text/template` is correct; the finding is only for HTML responses.
- **`os.Open` on a path built from constants.** Traversal needs caller influence; check the argument's origin.
- **Missing `ReadTimeout` on a server behind a proxy that enforces one.** Still defence in depth, but check the proxy configuration before filing it as the primary finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `go-net-http-and-gin-security` based solely on surface keywords (`ReadHeaderTimeout`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `go-net-http-and-gin-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: go-net-http-and-gin-security
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-400, CWE-918`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `go-net-http-and-gin-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-400, CWE-918`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 1 |
| Top sources | securecode-web (16) |
| Worked contrasts & slot items | 1 inline worked contrast + 8 code / 0 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
