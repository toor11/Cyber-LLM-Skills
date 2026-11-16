# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`defi-attack-patterns-amm-and-liquidity`](SKILL.md) | Family: **Blockchain**

Probes for `defi-attack-patterns-amm-and-liquidity`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Invariant before and after

Baseline: `k` before the operation. Probe: `k` after. Differential: a decrease beyond rounding means the pool leaked value.

```bash
cast call $POOL 'getReserves()(uint112,uint112,uint32)' --rpc-url $RPC --block $BLOCK
forge test --match-test testSwapInvariant -vvv --fork-block-number 19000000
```

## First-mint share price

Baseline: the minimum liquidity burned on first mint. Probe: the share amount for a second deposit. Differential: an extreme ratio is the mint-inflation path.

```bash
cast call $POOL 'totalSupply()(uint256)' --rpc-url $RPC --block $BLOCK
cast call $POOL 'balanceOf(address)(uint256)' 0x000000000000000000000000000000000000dEaD --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
