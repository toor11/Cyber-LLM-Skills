# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`go-ssa-and-rust-clippy-security-lints`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** `golang.org/x/tools/go/analysis` with `buildssa`; Rust dylint or `rustc` lint pass with UI fixtures.
- **Validation Gate:** `go test ./mylint -run TestAnalyzer` for the fixture pair, then `go vet -vettool` against a real package.
- Pin the `x/tools` version: SSA APIs change between minor releases and a floating dependency breaks the analyzer silently.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `go vet` | `go vet -vettool=$(go env GOPATH)/bin/mylint ./...` | Run the custom analyzer across a package tree | Cross-platform |
| `go test` | `go test ./mylint -run TestAnalyzer -v` | Fixture-driven analyzer test via analysistest | Cross-platform |
| `cargo dylint` | `cargo dylint --path ./lints -- --all-targets` | Run a dylint crate against the workspace | Linux, macOS, Windows |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```go
package unsafecall

import (
    "strings"

    "golang.org/x/tools/go/analysis"
    "golang.org/x/tools/go/ssa"
    "golang.org/x/tools/go/analysis/passes/buildssa"
)

var Analyzer = &analysis.Analyzer{
    Name:     "unsafecall",
    Doc:      "report calls into package unsafe",
    Requires: []*analysis.Analyzer{buildssa.Analyzer},
    Run:      run,
}

func run(pass *analysis.Pass) (any, error) {
    src := pass.ResultOf[buildssa.Analyzer].(*buildssa.SSA)
    for _, fn := range src.SrcFuncs {
        for _, b := range fn.Blocks {
            for _, ins := range b.Instrs {
                call, ok := ins.(ssa.CallInstruction)
                if !ok {
                    continue
                }
                callee := call.Common().StaticCallee()
                if callee != nil && strings.HasPrefix(callee.Pkg.Pkg.Path(), "unsafe") {
                    pass.Reportf(call.Pos(), "call into unsafe: %s", callee.Name())
                }
            }
        }
    }
    return nil, nil
}
```
