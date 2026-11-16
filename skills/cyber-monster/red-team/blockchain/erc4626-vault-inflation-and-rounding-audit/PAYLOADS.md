# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`erc4626-vault-inflation-and-rounding-audit`](SKILL.md) | Family: **Blockchain**

Probes for `erc4626-vault-inflation-and-rounding-audit`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Round-trip property

Baseline: a deposit then an immediate redeem of the same amount. Probe: the same with fuzzed amounts. Differential: assets returned greater than assets deposited, at any amount, is the finding.

```solidity
function testFuzzRoundTrip(uint256 amount) public {
    amount = bound(amount, 1, 1e30);
    uint256 shares = vault.previewDeposit(amount);
    uint256 back = vault.previewRedeem(shares);
    assertLe(back, amount, "vault paid out more than it took in");
}
```

## Donation sensitivity

Baseline: the share price for one asset. Probe: the share price after a direct transfer to the vault. Differential: a changed price with no deposit event means `totalAssets()` reads the live balance.

```bash
cast call $VAULT 'convertToAssets(uint256)(uint256)' 1000000000000000000 --rpc-url $RPC --block $BLOCK
cast call $VAULT 'totalAssets()(uint256)' --rpc-url $RPC --block $BLOCK
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
