# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`race-conditions-and-concurrency`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Report Template: Race Condition

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An attacker can exploit the race condition to [specific impact: double a payment, use coupon multiple times, vote multiple times, etc.].
- **Actionable Takeaway:** 1. Implement pessimistic locks (SELECT FOR UPDATE) 2. Use atomic transactions 3. Implement single-use tokens with immediate invalidation 4. Use idempotent operations with idempotency keys

## Case 2: Race Condition allows to redeem multiple times gift cards which leads to free "money"

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello team! I've found a Race Condition vulnerability which allows to redeem gift cards multiple times. This how a s/he can easily buy stuff just bying one gift card and redeem it over and over again.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Race condition in performing retest allows duplicated payments

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary There exists a race condition in performing retests. By executing multiple requests to confirm a retest at the same time, a malicious user is paid multiple times for the retest.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Client-Side Race Condition using Marketo, allows sending user to data-protocol in Safari when form withou

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I made a talk earlier this month about Client-Side Race Conditions for postMessage on AppSecEU: https://speakerdeck.com/fransrosen/owasp-appseceu-2018-attacking-modern-web-technologies In this talk I mention some fun ways to race postMessages from a malicious origin before...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Race Condition leads to undeletable group member

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, **Summary:** There exists a Race Condition in which the user can add themselves twice to a group which will make them unremovable from group. They themselves cannot remove themselves from the group as well as the group leader cannot remove that user from the group.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Race Conditions in Popular reports feature.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** This vulnerability allows you to explore a race condition bug on a new feature of hackerone, the popular reports.. To reproduce this bug, you need to intercept the POST request that trigger the "upvote" action.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Race Condition when following a user

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi team, There is a race condition vulnerability when following a user. If you send the 'Follow' requests asynchronously, you can follow a user multiple times instead getting an error message.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Race Condition in Flag Submission

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** This report describes a Race Condition Vulnerability which allow an authenticated user to submit the same Flag multiple times. Increasing the user points and therefore the chances to get an invitation to a private program.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
