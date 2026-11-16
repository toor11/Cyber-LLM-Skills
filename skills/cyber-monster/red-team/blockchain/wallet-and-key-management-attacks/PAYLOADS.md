# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`wallet-and-key-management-attacks`](SKILL.md) | Family: **Blockchain**

Probes for `wallet-and-key-management-attacks`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Approval inventory

Baseline: the intended allowance. Probe: the on-chain allowance at a block. Differential: an allowance above the intended amount, or with no expiry mechanism, is standing authority to report.

```bash
cast call $TOKEN 'allowance(address,address)(uint256)' $OWNER $SPENDER --rpc-url $RPC --block $BLOCK
cast call $TOKEN 'balanceOf(address)(uint256)' $OWNER --rpc-url $RPC --block $BLOCK
```

## Signature replay

Baseline: a signature used once, which must succeed. Probe: the same signature used again. Differential: a second success means no nonce or deadline is enforced.

```bash
cast send $CONTRACT 'permitAndPull(address,uint256,uint256,uint8,bytes32,bytes32)' $OWNER 1 $DEADLINE $V $R $S --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
