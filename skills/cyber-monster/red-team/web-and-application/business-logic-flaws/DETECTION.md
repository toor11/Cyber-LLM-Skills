# Detection Signals and Blue-Team Handoff

> Sub-skill: [`business-logic-flaws`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Order-service logs where a submitted `total`, `unitPrice`, or `amount` differs from the server-recomputed value for the same line items.
- Checkout events with `quantity` <= 0 or a non-integer quantity reaching the order table.
- Coupon-service records showing the same promotion code applied more than once to a single cart or order id.
- Two settlement or redemption rows for the same idempotency key or voucher within the same millisecond window.
- Workflow audit entries where an order status advances to `paid` or `shipped` without the preceding `authorised` transition.
- Refund-ledger entries whose credited amount exceeds the captured amount on the referenced payment.
- A spike in successful discount application on one promotion code relative to the number of codes issued.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
