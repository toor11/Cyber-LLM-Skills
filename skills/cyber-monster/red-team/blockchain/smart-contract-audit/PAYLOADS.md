# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Probes for `smart-contract-audit`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Entrypoint inventory

Baseline: the public ABI. Probe: functions that move value or change privileged state. Differential: a fund-moving function with no authorisation check is the review's first target.

```bash
forge inspect Bank abi --json | jq '[.[] | select(.type=="function") | {name, stateMutability}]'
slither . --print human-summary
```

## Invariant falsification

Baseline: the invariant holds across a benign sequence. Probe: the invariant after a crafted sequence. Differential: a broken invariant with a shrinking sequence is the finding.

```bash
forge test --match-contract BankInvariant -vvv
cast call $BANK 'balances(address)(uint256)' $USER --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
