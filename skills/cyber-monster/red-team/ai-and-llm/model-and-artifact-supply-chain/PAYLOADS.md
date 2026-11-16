# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`model-and-artifact-supply-chain`](SKILL.md) | Family: **AI and LLM**

Probes for `model-and-artifact-supply-chain`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Hash verification gate

Baseline: the hash recorded in the manifest. Probe: the hash of the downloaded artefact. Differential: a mismatch must stop the load; a pipeline that continues is the finding.

```bash
sha256sum model.safetensors
python -c "import json; print(json.load(open('manifest.json'))['weights_sha256'])"
```

## Loader format check

Baseline: the loader used in production. Probe: whether it can deserialise a pickle. Differential: a pickle-capable loader is an execution path even when the current file is safe.

```bash
python -c "import torch; print(torch.load)"
python -c "from safetensors.torch import load_file; print(load_file)"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
