# Evidence and Attestation Queries

> Sub-skill: [`business-email-compromise-response`](SKILL.md) | Family: **Incident Response**

Queries owned by `business-email-compromise-response`, grouped by the evidence question they answer. In a BEC case the audit log is the case: each class below either proves the actor did something, proves the responder's action took effect, or proves the tenant cannot answer the question at all. Verify field names against your own unified audit log export before deployment.

## Class 1 — Audit coverage attestation (run first)

Expected hit: at least one mailbox-audit and one sign-in record per affected principal inside the dwell window, with `Operation` values populated rather than null. Coverage that starts after the actor's first sign-in makes every later class conditional.

```kusto
AuditLogs
| where TimeGenerated between (ago(120d) .. now())
| where Category in ("MailboxAudit", "AzureActiveDirectoryStsLogon")
| summarize rows = count(), first_seen = min(TimeGenerated), last_seen = max(TimeGenerated)
  by Category, Operation = tostring(OperationName)
| order by rows desc
```

False-positive note: an operation absent from the summary may be unlicensed rather than unperformed — mailbox auditing requires the right plan, and a missing `New-InboxRule` row on an unlicensed mailbox is a coverage gap, not innocence.

## Class 2 — Mailbox rule creation and its target

Expected hit: a rule-management event whose parameters carry `ForwardTo`, `RedirectTo` or `MoveToFolder`, created after the first unfamiliar sign-in for the same principal. The rule id and destination address are the evidence; the rule itself is not.

```kusto
CloudAppEvents
| where TimeGenerated between (ago(60d) .. now())
| where ActionType has_any ("InboxRule", "UpdateInboxRules")
| extend p = tostring(RawEventData)
| extend dest = extract(@'"(?:ForwardTo|RedirectTo)"\s*:\s*\[?"?([^"\],\s]+)', 1, p)
| extend folder = extract(@'"MoveToFolder"\s*:\s*"?([^",]+)', 1, p)
| where isnotempty(dest) or folder has_any ("Rss", "Archive", "Conversation History")
| project TimeGenerated, AccountUpn, ActionType, dest, folder
| sort by TimeGenerated asc, OperationName asc
```

False-positive note: rules created by journaling, archiving and ticketing connectors have external destinations by design and appear here; exclude documented connector principals before scoring.

## Class 3 — Token and consent attestation after revocation

Expected hit: zero successful interactive or non-interactive sign-ins for the principal from the actor's infrastructure after the revocation timestamp, and a `Consent` or `Add service principal` record showing the grant that was revoked. A post-revocation success proves a surviving token or an unrevoked grant.

```kusto
let revokedAt = datetime(2026-11-14T09:12:00Z);
AADSignInEventsBeta
| where Timestamp > revokedAt
| where AccountUpn == "target@contoso.com"
| extend viaActorRange = ipv4_is_in_any_range(IPAddress, dynamic(["198.51.100.0/24"]))
| summarize attempts = count(), allowed = countif(ErrorCode == 0)
  by Bin = bin(Timestamp, 30m), AppDisplayName, viaActorRange
| where viaActorRange
| sort by Bin asc
```

False-positive note: continuous access evaluation propagates a revocation within minutes, not instantly, and can take up to 15 minutes; a success inside that window is expected and must be timestamped, not treated as a surviving token.

## Class 4 — Exfiltration and recipient enumeration

Expected hit: `Send` and `MailItemsAccessed` events by the actor's session inside the window, each with an internet message id, resolving to external recipients. This class produces the notification list; it is also what proves disclosure scope.

```kusto
CloudAppEvents
| where TimeGenerated between (ago(60d) .. now())
| where ActionType in ("Send", "MailItemsAccessed", "SendAs", "SendOnBehalf")
| where AccountUpn == "target@contoso.com"
| extend raw = tostring(RawEventData)
| extend msgid = extract(@'"InternetMessageId"\s*:\s*"([^"]+)', 1, raw)
| summarize sends = count(), first_send = min(TimeGenerated), last_send = max(TimeGenerated),
            messages = make_set(msgid, 20)
  by AccountUpn, ActionType
```

False-positive note: `MailItemsAccessed` fires for ordinary client synchronisation and will always show volume; only the subset inside the actor's session identifiers should be counted as access.

## Class 5 — Payment instruction and fraud-loss artefacts

Expected hit: messages in the actor's session whose body or attachment references bank details, invoice numbers, or a changed remittance account. This is what the bank fraud team needs and what legal needs for disclosure.

```text
disclosure_attestation:
  source:          unified audit log Send events, actor session ids only
  extract:         internet message id, recipients, subject, hashed body
  correlate_with:  accounts-payable ticket ids for the same window
  expected:        the message the counterparty acted on, with its timestamp
  blind_spot:      bodies are not retained by default in some plans; then the
                   recipient's copy is the only surviving evidence
```

False-positive note: a legitimate banking-detail change notified by the vendor looks identical; confirm the change through a channel the vendor did not control before classifying it as fraud.

## Class 6 — MFA method and re-enrolment state

Expected hit: a method-registration event for the actor followed by a removal and a user re-registration event out of band. Without the second pair the account returns to the actor at the next sign-in.

```kusto
AuditLogs
| where TimeGenerated between (ago(90d) .. now())
| where OperationName has_any ("security info", "StrongAuthentication", "Authentication Method")
| where TargetResources has "target@contoso.com"
| project TimeGenerated, OperationName, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
          Result = tostring(Result)
| sort by TimeGenerated asc, Result asc
```

False-positive note: SSPR-driven re-registration after a legitimate device loss produces the same sequence; the discriminator is the ticket and the caller verification, not the event shape.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the audit retention boundary next to every saved query; a BEC timeline that reaches past retention must be labelled as reconstructed from mailboxes rather than from logs.
