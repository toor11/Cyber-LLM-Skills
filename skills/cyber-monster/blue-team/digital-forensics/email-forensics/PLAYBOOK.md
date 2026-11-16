# Operational Triage and Response Playbook

> Sub-skill: [`email-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `email-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

Email evidence is unusually easy to destroy while trying to read it: a mail client that opens a store rewrites it, a forward re-serialises headers, a preview handler fetches remote content and tells the sender the message was opened. The runbook therefore keeps every interaction with the message textual and offline, and it separates the two questions that get conflated — what the message claims about its origin, and what your own infrastructure recorded about its delivery.

## Triggers

- Alert, hunt outlier, or review request matching `email forensics`.
- Alert, hunt outlier, or review request matching `header analysis email`.
- Alert, hunt outlier, or review request matching `mailbox forensics`.
- A user reports a message, and the question is whether it came from where it claims.
- An account sends mail it did not author, and the question is which hop and which credential were involved.
- A mailbox rule, forwarding setting or delegate changed, and the question is what arrived before the change.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `Authentication-Results` from your boundary shows `dmarc=fail` with a non-aligning envelope, plus a first hop outside the sender's ranges | Confirmed spoofed origin | Preserve the raw EML and the transport log for the queue ID; scope who else received the same `Message-ID` |
| Attachment SHA-256 matches a file-write record on a recipient host | Confirmed delivery and execution path | Preserve the host artifact evidence; hand the sample to malware triage with the hash, not the mailbox |
| Broken DKIM body hash on a message that passed through a known mailing list | Benign Baseline (list rewriting) | Record the list; no forgery finding, but keep the message for the record |
| Chain short with no hop written by your boundary | Inconclusive (Boundary Not Reached) | Check whether the message entered via a route your boundary does not log, and record the route gap |
| Item present in an OST cache but absent from the server-side mailbox | Inconclusive (Cache Divergence) | Query the platform audit log for the item's operations before concluding deletion |
| Mailbox audit log empty for a mailbox that should have auditing | Inconclusive (Telemetry Gap) | Do NOT close as clean; record the audit policy state and the licensing prerequisite |
| `Received:` hop time earlier than its predecessor by minutes | Clock skew, not tampering | Read the sending MTA's time source and the skew magnitude before considering any other explanation |

## Containment and Recovery

1. **Preserve before mutating:** export the raw message with full headers and hash it, then the mailbox items in scope, then the platform audit log for the window. Do not delete the message from the mailbox first — the server-side copy is often the only authoritative record of its arrival.
2. **Search before you purge:** run a tenant-wide search on the `Message-ID`, the sending infrastructure and the attachment hash to find every copy, including forwarded and rule-moved items, before any remediation removes them.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and for mail, never block an entire sending domain or ESP range without confirming which legitimate business mail depends on it.
4. **Contain the identity, not only the message:** if a mailbox rule, delegate or OAuth grant was the mechanism, revoke the grant and the sessions, and check the audit log for what the rule forwarded before it was removed. Removing the rule destroys the evidence of what it did.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the vector was an unenforced DMARC policy or a missing attachment control, fix the control tenant-wide rather than adding a rule for one sender.
