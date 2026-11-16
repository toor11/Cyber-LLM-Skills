# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`governance-and-token-attacks`](SKILL.md) | Family: **Blockchain**

Probes for `governance-and-token-attacks`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Capture cost

Baseline: the value a proposal can move. Probe: the cost of acquiring the threshold. Differential: a positive margin is the finding.

```bash
cast call $TOKEN 'balanceOf(address)(uint256)' $GOV --rpc-url $RPC
cast call $GOV 'threshold()(uint256)' --rpc-url $RPC
```

## Same-block reward capture

Baseline: rewards accrued by a position held across the distribution. Probe: rewards claimed by a deposit made in the distribution block. Differential: a non-zero claim for a position that did not exist during accrual is the finding.

```solidity
function testSameBlockClaim() public {
    vm.roll(100);
    gov.deposit(1_000e18);
    vm.roll(101);
    uint256 before = token.balanceOf(address(this));
    gov.claim();
    assertEq(token.balanceOf(address(this)) - before, 0);
}
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
