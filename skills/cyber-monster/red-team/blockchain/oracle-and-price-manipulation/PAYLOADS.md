# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`oracle-and-price-manipulation`](SKILL.md) | Family: **Blockchain**

Probes for `oracle-and-price-manipulation`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Freshness check

Baseline: the current `updatedAt`. Probe: the same read after the heartbeat interval. Differential: an answer older than the protocol's threshold with no revert is the finding.

```bash
cast call $FEED 'latestRoundData()(uint80,int256,uint256,uint256,uint80)' --rpc-url $RPC
cast block latest --field timestamp --rpc-url $RPC
```

## Permitted movement versus decision

Baseline: the borrow limit at the current price. Probe: the limit at a price moved within the deviation bound. Differential: a material change in the limit is the exposure.

```bash
cast call $LENDING 'borrowLimit(address)(uint256)' $USER --rpc-url $RPC
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
