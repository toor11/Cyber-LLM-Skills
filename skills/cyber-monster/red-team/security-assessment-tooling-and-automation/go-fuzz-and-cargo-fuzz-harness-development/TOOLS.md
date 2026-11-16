# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`go-fuzz-and-cargo-fuzz-harness-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Go 1.20+ native fuzzing; cargo-fuzz on nightly with `arbitrary` for derived inputs.
- **Validation Gate:** `go test -run=Fuzz -v` then one timed `-fuzz` run; `cargo fuzz build` before `cargo fuzz run`.
- Go fuzz crashers land in `testdata/fuzz/<FuzzName>/` and are replayed by a plain `go test`; commit them as regression seeds.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `go test` | `go test -run=^$ -fuzz=FuzzParse -fuzztime=30s` | Timed fuzz campaign with the native engine | Cross-platform |
| `cargo fuzz` | `cargo +nightly fuzz run parse_target -- -max_total_time=60` | Coverage-guided Rust campaign via libFuzzer | Linux, macOS, Windows WSL |
| `go tool cover` | `go test -coverprofile=cover.out ./...` | Confirm the harness reaches the intended package | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```go
package parse

import "testing"

func FuzzParse(f *testing.F) {
    f.Add([]byte("v=1"), []byte("a=b"))
    f.Fuzz(func(t *testing.T, head, body []byte) {
        if len(head) == 0 {
            return
        }
        _, _ = ParseWithHeader(head, body)
    })
}
```
