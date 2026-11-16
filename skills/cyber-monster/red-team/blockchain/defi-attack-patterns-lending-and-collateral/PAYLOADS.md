# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`defi-attack-patterns-lending-and-collateral`](SKILL.md) | Family: **Blockchain**

Probes for `defi-attack-patterns-lending-and-collateral`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Buffer check

Baseline: the maximum borrow at the collateral factor. Probe: the health factor after a 5% adverse move. Differential: a health factor below one after a normal move is the finding.

```bash
cast call $MARKET 'collateralFactor()(uint256)' --rpc-url $RPC
cast call $MARKET 'healthFactor(address)(uint256)' $USER --rpc-url $RPC
```

## Liquidation economics

Baseline: the bonus a liquidator receives. Probe: the bonus minus gas and swap cost on a marginal position. Differential: a positive net value on a barely-unhealthy position incentivises liquidation for profit.

```solidity
function testLiquidationProfitAtThreshold() public {
    _openAtMaxLtv();
    _dropPrice(1);
    uint256 profit = market.liquidationProfit(address(this));
    assertLe(profit, 0, "no profit on a marginal position");
}
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
