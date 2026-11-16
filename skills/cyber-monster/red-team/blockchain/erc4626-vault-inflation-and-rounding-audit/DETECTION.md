# Detection Signals and Blue-Team Handoff

> Sub-skill: [`erc4626-vault-inflation-and-rounding-audit`](SKILL.md) | Family: **Blockchain**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- A first deposit of one wei followed by a large direct transfer to the vault, the classic inflation setup.
- Share price changes with no `Deposit` or `Withdraw` event in the same block.
- A large number of tiny deposits from one address, characteristic of rounding extraction.
- Withdrawals that burn fewer shares than the assets redeemed, visible as an increasing assets-per-share ratio.
- Direct ERC-20 transfers to the vault contract from an address with no position.
- Redeem calls immediately following a deposit in the same block.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) | Query authoring, triage, and hardening |
