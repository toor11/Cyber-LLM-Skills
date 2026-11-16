# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`libfuzzer-and-afl-harness-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `libfuzzer-and-afl-harness-engineering`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Corpus sanity run

Baseline: every seed executes clean at `-runs=0`. Probe: the campaign. Differential: a crash that also fires from the seed is a corpus defect.

```bash
./fuzz -runs=0 corpus/
./fuzz -runs=200000 -max_len=4096 -print_final_stats=1 corpus/
```

## AFL++ corpus minimisation

Baseline: the raw corpus size. Probe: the minimised corpus. Differential: the minimised corpus must keep the same edge count with fewer inputs.

```bash
afl-cmin -i corpus -o corpus_min -- ./target @@
afl-showmap -i corpus_min -o /dev/null -- ./target @@
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
