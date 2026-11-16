# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`wallet-and-key-management-attacks-approval-and-permit-abuse`](SKILL.md) | Family: **Blockchain**

Probes for `wallet-and-key-management-attacks-approval-and-permit-abuse`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Allowance versus need

Baseline: the amount the operation requires. Probe: the granted allowance. Differential: a grant orders of magnitude above the need, with no reset, is standing authority to report.

```bash
cast call $TOKEN 'allowance(address,address)(uint256)' $OWNER $SPENDER --block $BLOCK --rpc-url $RPC
cast call $TOKEN 'balanceOf(address)(uint256)' $OWNER --block $BLOCK --rpc-url $RPC
```

## Expired permit

Baseline: a permit with a future deadline, which must succeed. Probe: the same signature after the deadline. Differential: a success means the deadline is not enforced.

```bash
cast send $STAKING 'stakeWithPermit(uint256,uint256,uint8,bytes32,bytes32)' 1 $PAST_DEADLINE $V $R $S --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
