# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`go-fuzz-and-cargo-fuzz-harness-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `go-fuzz-and-cargo-fuzz-harness-development`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Seed-only baseline

Baseline: run the harness over the seed corpus without fuzzing. Probe: the same harness under fuzzing. Differential: coverage growth only counts if the baseline already executed the parser.

```bash
go test -run=FuzzParse -v ./...
go test -run=^$ -fuzz=FuzzParse -fuzztime=60s ./...
```

## Rust target replay

Baseline: the committed corpus under `fuzz/corpus`. Probe: the artefact under `fuzz/artifacts`. Differential: the artefact must panic on replay, the corpus must not.

```bash
cargo +nightly fuzz run parse_target fuzz/corpus/parse_target
cargo +nightly fuzz run parse_target fuzz/artifacts/parse_target/crash-*
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
