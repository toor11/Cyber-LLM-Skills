# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`nuclei-template-engineering`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `nuclei-template-engineering`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Vulnerable vs patched differential

Baseline: the template against a patched instance must produce no match. Probe: against a vulnerable instance it must match. Differential: a match on both is a template defect.

```bash
nuclei -validate -t template.yaml
nuclei -t template.yaml -u https://patched.example -silent
nuclei -t template.yaml -u https://vulnerable.example -silent
```

## Matcher specificity check

Baseline: the endpoint's own body. Probe: a random path on the same host. Differential: identical results mean the matcher is matching the shell.

```bash
curl -sS -D- https://target.example/config.json -o /dev/null
curl -sS https://target.example/does-not-exist-$(date +%s) | head -c 200
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
