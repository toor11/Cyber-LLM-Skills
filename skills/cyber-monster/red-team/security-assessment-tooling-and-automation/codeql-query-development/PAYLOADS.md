# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`codeql-query-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `codeql-query-development`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Query compile gate

Baseline: the query compiles against the pinned packs. Probe: the same compile against the target database's language pack. Differential: a compile failure means the API used is not in that pack.

```bash
codeql query compile --search-path ./codeql-packs MyQuery.ql
codeql database analyze db MyQuery.ql --format=sarif-latest --output=out.sarif
```

## Fix-commit differential

Baseline: results on the vulnerable commit. Probe: results on the fix commit. Differential: the specific path must disappear; a surviving path is a query calibration problem.

```bash
codeql database create db-vuln --language=python --source-root ./vuln
codeql database create db-fix --language=python --source-root ./fix
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
