# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`nmap-nse-audit-script-authoring`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `nmap-nse-audit-script-authoring`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Positive and negative host pair

Baseline: a host without the condition must produce no matching field. Probe: a host with the condition must produce it. Differential: the field's presence is the finding.

```bash
nmap --script ./audit.nse -p 443 known-good.example
nmap --script ./audit.nse -p 443 known-bad.example
```

## Script argument gate

Baseline: run with the script disabled by category. Probe: run with the category selected. Differential: output only in the selected run confirms the category gating works.

```bash
nmap -sV -p 443 target.example
nmap --script ./audit.nse -p 443 target.example
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
