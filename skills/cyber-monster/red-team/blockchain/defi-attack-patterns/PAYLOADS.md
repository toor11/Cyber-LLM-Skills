# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`defi-attack-patterns`](SKILL.md) | Family: **Blockchain**

Probes for `defi-attack-patterns`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Spot versus time-weighted quote

Baseline: the quoted value at the pinned block. Probe: the value inside a transaction that moves the pool. Differential: a large change in the spot quote with an unchanged TWAP identifies the manipulable input.

```bash
cast call $PAIR 'getReserves()(uint112,uint112,uint32)' --rpc-url $RPC
cast call $POOL 'observe(uint32[2])(uint256[2],int24[2])' 0 --rpc-url $RPC
```

## Donation sensitivity

Baseline: share price before a direct transfer. Probe: share price after transferring tokens to the contract. Differential: a price change with no deposit indicates balance-based accounting.

```bash
cast call $VAULT 'totalAssets()(uint256)' --rpc-url $RPC
cast call $VAULT 'convertToAssets(uint256)(uint256)' 1000000000000000000 --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
