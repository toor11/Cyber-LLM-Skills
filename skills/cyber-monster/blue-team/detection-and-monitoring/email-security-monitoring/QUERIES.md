# Detection Queries and Telemetry Artifacts

> Sub-skill: [`email-security-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Blocks are grouped by case class: authentication failures on owned domains, impersonation of owned identities, and mailbox compromise. Field names follow the Microsoft Defender XDR advanced-hunting `EmailEvents` schema; substitute your own mail-flow table after confirming the column set, and see [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) for base-search mechanics in other backends.

## Class 1 — Authentication decomposition on owned domains

Expected hit: inbound or intra-org messages whose `From` domain is one you own while SPF, DKIM, or DMARC failed. This is a brand forgery and the sender address is one your edge observed.

```kusto
let own = dynamic(["contoso.com","contoso-mail.com"]);
EmailEvents
| where Timestamp > ago(168h)
| where EmailDirection in ("Inbound","Intra-org")
| extend auth = parse_json(AuthenticationDetails)
| extend spf = tostring(auth.SPF), dkim = tostring(auth.DKIM),
         dmarc = tostring(auth.DMARC), comp = tostring(auth.CompAuth)
| extend from_domain = tolower(tostring(split(SenderFromAddress, "@")[1]))
| where from_domain in (own)
| where spf == "fail" or dkim == "fail" or dmarc == "fail" or comp == "fail"
| summarize attempts=count(), senders=make_set(SenderFromAddress, 10),
            ips=make_set(SenderIPv4, 10), first=min(Timestamp), last=max(Timestamp)
            by from_domain, SenderIPv4, bin(Timestamp, 1h)
| order by attempts desc, codes asc
```

False-positive note: a legitimate third-party sender using your domain with a stale DKIM selector appears here continuously until its DNS record is updated; confirm the selector and the sending service before treating the volume as hostile.

## Class 2 — Look-alike `From` domain for an owned identity

Expected hit: an external `From` domain whose registrable part is close to one you own, paired with a display name matching an internal person. Exact string comparison plus a normalised skeleton comparison is what catches homoglyph and transposition tricks.

```kusto
let own = dynamic(["contoso.com"]);
let internal_names = IdentityInfo
| where Timestamp > ago(60d)
| project AccountDisplayName=tolower(AccountDisplayName);
EmailEvents
| where Timestamp > ago(168h)
| where EmailDirection == "Inbound"
| extend from_domain = tolower(tostring(split(SenderFromAddress, "@")[1]))
| extend display = tolower(tostring(SenderDisplayName))
| where from_domain !in (own)
| where display in (internal_names)
| extend skeleton = replace_string(replace_string(from_domain, "0", "o"), "1", "l")
| where skeleton has_any ("contoso", "contos0", "ccontoso")
| summarize hits=count(), first=min(Timestamp), subjects=make_set(Subject, 5)
            by from_domain, SenderFromAddress, display
| order by hits desc
```

False-positive note: a genuine partner whose company name embeds yours (`contoso-partners.example`) will match a skeleton comparison; check the relationship history and the message content before escalating.

## Class 3 — First-contact relationship (BEC shape)

Expected hit: an internal account emailing an external recipient domain it has never contacted, especially where the subject or body references payment or account changes. Authentication is irrelevant to this query by design.

```kusto
EmailEvents
| where Timestamp > ago(168h)
| where EmailDirection == "Outbound"
| extend sender = tolower(SenderFromAddress)
| extend rcpt_domain = tolower(tostring(split(RecipientEmailAddress, "@")[1]))
| summarize first_seen=min(Timestamp), msgs=count() by sender, rcpt_domain
| join kind=leftanti hint.strategy=shuffle (
    EmailEvents
    | where Timestamp between (ago(90d) .. ago(7d))
    | where EmailDirection == "Outbound"
    | extend sender = tolower(SenderFromAddress)
    | extend rcpt_domain = tolower(tostring(split(RecipientEmailAddress, "@")[1]))
    | distinct sender, rcpt_domain
  ) on sender, rcpt_domain
| where msgs >= 1
| order by first_seen desc
```

False-positive note: a new customer or supplier legitimately creates a first contact; the query produces candidates, so pair it with a content signal or with mailbox-rule evidence before escalating.

## Class 4 — Mailbox rule and forwarding changes

Expected hit: rule creation, forwarding enablement, or inbox manipulation for an account that also shows outbound anomalies. This is the compromise evidence that authentication cannot supply.

```kusto
CloudAppEvents
| where Timestamp > ago(168h)
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Set-Mailbox","Add-MailboxPermission")
| extend actor = tostring(AccountId)
| extend params = tostring(RawEventData)
| where params has_any ("ForwardTo","RedirectTo","MoveToFolder","DeleteMessage","MarkAsRead")
| summarize events=count(), first=min(Timestamp), last=max(Timestamp),
            types=make_set(ActionType, 5) by actor
| order by events desc, actor asc, types asc
```

False-positive note: helpdesk automation and mail-flow rules create inbox rules programmatically under service accounts; confirm the actor's identity type and the client application before attributing the rule to a person.

## Class 5 — Outbound recipient-domain spike per account

Expected hit: one account whose distinct external recipient count in an hour far exceeds its own trailing baseline. A compromised mailbox used for internal phishing shows exactly this.

```spl
index=email sourcetype="email:message" earliest=-14d@d latest=@d
| eval direction = lower(direction)
| where direction=="outbound"
| eval rcpt_domain = lower(mvindex(split(recipient, "@"), 1))
| bin _time span=1h
| stats dc(rcpt_domain) AS domains, count AS msgs by _time, sender
| eventstats median(domains) AS med, median(abs(domains - median(domains))) AS mad by sender
| where _time >= relative_time(now(), "-1d@d") AND domains > med + (6 * mad) AND domains > 20
| sort - domains
```

False-positive note: a campaign send or a ticketing migration raises both `domains` and `msgs` for one account; check whether the sending application identity matches the mailbox owner before escalating.

## Class 6 — Attachment structure profile

Expected hit: attachment types whose structure does not match their extension, or document types carrying embedded URLs or macro streams. Static structural triage precedes any detonation.

```spl
index=email sourcetype="email:attachment" earliest=-7d@d latest=@d
| eval ext = lower(mvindex(split(file_name, "."), -1))
| eval magic = lower(file_magic)
| where (ext=="pdf" AND NOT match(magic, "pdf")) OR (ext IN ("doc","docx","xls","xlsx") AND match(magic, "zip|ole"))
| stats count AS attachments, values(file_name) AS names, dc(sender) AS senders by ext, magic
| sort - attachments
```

False-positive note: modern Office formats are zip containers by design, so the `zip` match on `docx` is expected; the signal is a mismatch between the declared extension and the container, not the container alone.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the tenant DMARC policy in force beside every authentication-based rule; the same rule means something different at `p=none` and at `p=reject`.
