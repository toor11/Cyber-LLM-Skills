# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`move-aptos-and-sui-smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Probes for `move-aptos-and-sui-smart-contract-audit`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Ability check

Baseline: the struct's declared abilities. Probe: a test that attempts to copy the resource. Differential: a compiling copy means the ability is present and supply accounting is broken.

```bash
aptos move test --filter test_ability
sui move test --filter test_ability
```

## Capability construction

Baseline: mint from inside the module. Probe: an attempt to construct the capability from an external module. Differential: a successful construction is the privilege escalation.

```bash
aptos move test --filter test_capability_forgery
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
