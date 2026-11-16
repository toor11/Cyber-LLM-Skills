# Detection Signals and Blue-Team Handoff

> Sub-skill: [`business-logic-flaws-payment-and-pricing`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Payment-service logs where request `price_cents` or `amount` differs from the catalogue price joined on sku.
- Order rows with a negative line amount or a total below the sum of catalogue line prices.
- Wallet or store-credit ledger entries created from an order whose captured amount was zero.
- Gateway webhook receipts marked paid where the stored provider signature did not validate.
- Refund-ledger rows whose amount exceeds the captured amount on the parent transaction.
- Repeated applications of one discount code on a single order id in the coupon-service log.
- An order currency differing from the store's configured settlement currency.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
