# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ai-application-assessment`](SKILL.md) | Family: **AI and LLM**

Probes for `ai-application-assessment`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Surface probe set

Baseline: a benign request per surface. Probe: one request that exercises the control on that surface. Differential: the control acting deterministically is a pass; model discretion is a gap.

```text
Prompt surface: injected document -> expect no tool call
Output surface: script tag in model output -> expect escaped rendering
Tool surface: hijacked context -> expect a proposed, not executed, action
Data surface: foreign-tenant chunk ingested -> expect no retrieval
```

## Tool privilege map

Baseline: the application's own role model. Probe: the credentials each tool holds. Differential: a tool with broader credentials than the requesting user is the finding.

```bash
python -c "import yaml; print(yaml.safe_load(open('surface-map.yaml'))['surfaces']['tools'])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
