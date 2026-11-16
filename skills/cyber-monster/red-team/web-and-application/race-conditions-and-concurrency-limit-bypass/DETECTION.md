# Detection Signals and Blue-Team Handoff

> Sub-skill: [`race-conditions-and-concurrency-limit-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Ledger rows where a one-use coupon or card records more than one redemption event.
- Balance audit entries showing a debit total exceeding the available amount within one second.
- Duplicate (user, token) redemption log lines committed concurrently.
- Vote or follow counters incremented multiple times by one user within the same window.
- OTP verification success logged twice for a single code.
- Database deadlock or lock-wait spikes on a wallet or voucher table during a burst.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
