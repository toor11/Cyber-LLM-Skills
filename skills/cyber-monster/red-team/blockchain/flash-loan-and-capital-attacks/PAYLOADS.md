# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`flash-loan-and-capital-attacks`](SKILL.md) | Family: **Blockchain**

Probes for `flash-loan-and-capital-attacks`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Flash capital differential

Baseline: the borrow limit without borrowed capital. Probe: the limit while holding a flash loan. Differential: a limit that increases with temporary capital is the exposure.

```solidity
function testFlashCollateral() public {
    flashLender.flashLoan(address(this), 1_000_000e18);
}
function onFlashLoan(uint256 amount) external {
    token.approve(address(market), amount);
    market.deposit(amount);
    market.borrow(amount * 2);
}
```

## Vote weight timing

Baseline: the voting weight at the snapshot block. Probe: the weight during the proposal window. Differential: a weight that follows a temporary balance indicates execution-time measurement.

```bash
cast call $GOV 'getVotes(address)(uint256)' $ATTACKER --block $SNAPSHOT --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
