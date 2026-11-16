# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`arithmetic-and-precision-bugs`](SKILL.md) | Family: **Blockchain**

Probes for `arithmetic-and-precision-bugs`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Exact versus integer math

Baseline: the contract's integer result. Probe: the exact rational result. Differential: the sign and size of the difference identifies which party the rounding favours.

```python
from fractions import Fraction
print(Fraction(10**18 - 1, 3), (10**18 - 1) // 3)
```

## Decimal sweep

Baseline: the calculation with an 18-decimal token. Probe: the same with a 6-decimal token. Differential: a result scaled by the wrong factor is the decimal bug.

```solidity
function testFuzzDecimals(uint256 amount, uint8 dec) public {
    dec = uint8(bound(dec, 6, 18));
    uint256 shares = rewards.toShares(amount, 1e18, dec);
    assertLe(shares, amount, "shares must not exceed assets");
}
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
