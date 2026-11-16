# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`reentrancy-and-call-ordering`](SKILL.md) | Family: **Blockchain**

Probes for `reentrancy-and-call-ordering`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Malicious receiver test

Baseline: a single withdrawal by a normal address succeeds once. Probe: the same withdrawal from a contract that re-enters. Differential: a second successful withdrawal, or a stale price read during the callback, is the finding.

```solidity
function onReceive() external payable {
    if (address(vault).balance >= 1 ether) vault.withdraw(1 ether);
}
```

## State consistency at the callback

Baseline: the share value after the transaction. Probe: the share value read inside the callback. Differential: a difference proves the view is stale during the window.

```bash
cast call $VAULT 'pricePerShare()(uint256)' --rpc-url $RPC
forge test --match-test testReadOnlyReentrancy -vvv
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
