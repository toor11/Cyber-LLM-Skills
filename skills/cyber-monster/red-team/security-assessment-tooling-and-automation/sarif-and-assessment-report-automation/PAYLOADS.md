# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sarif-and-assessment-report-automation`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `sarif-and-assessment-report-automation`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Schema validation gate

Baseline: a valid SARIF document. Probe: the pipeline's own output. Differential: the output must validate, and a validation failure must stop the pipeline.

```bash
python -c "import json; d=json.load(open('out.sarif')); print(d['version'], len(d['runs']))"
python -c "import json; d=json.load(open('out.sarif')); print(sum(len(r.get('results', [])) for r in d['runs']))"
python -c "import json; d=json.load(open('out.sarif')); print(sorted({r['ruleId'] for run in d['runs'] for r in run.get('results', [])}))"
```

## Fingerprint stability check

Baseline: fingerprints from run one. Probe: fingerprints from run two on the same code. Differential: identical sets; any drift means the fingerprint inputs changed.

```bash
jq -r '.runs[].results[].partialFingerprints.primaryLocationLineHash' out.sarif | sort | sha256sum
jq -r '.runs[].results[].ruleId' out.sarif | sort -u
jq '.runs | length' out.sarif
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
