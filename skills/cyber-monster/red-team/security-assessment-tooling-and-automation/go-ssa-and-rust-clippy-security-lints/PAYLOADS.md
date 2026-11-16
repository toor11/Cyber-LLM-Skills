# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`go-ssa-and-rust-clippy-security-lints`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `go-ssa-and-rust-clippy-security-lints`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Fixture pair gate

Baseline: the negative fixture must produce no diagnostic. Probe: the positive fixture must produce exactly its `// want` annotation. Differential: any mismatch fails the gate.

```bash
go test ./mylint -run TestAnalyzer -v
go vet -vettool=./bin/mylint ./internal/...
```

## Rust lint fixture

Baseline: a crate using the safe helper. Probe: the same crate calling the raw API. Differential: the diagnostic must appear only in the second.

```bash
cargo dylint --path ./lints -- --all-targets
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
