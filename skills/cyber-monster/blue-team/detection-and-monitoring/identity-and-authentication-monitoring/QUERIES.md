# Detection Queries and Telemetry Artifacts

> Sub-skill: [`identity-and-authentication-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Each class reads one of the three event families — interactive sign-ins, non-interactive sign-ins, and directory audit — and states which family it uses. Field names follow the Microsoft Entra ID schema exposed through Sentinel (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`); substitute your IdP's equivalents after confirming the columns, and see [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) for base-search semantics elsewhere.

## Class 1 — Failure-reason decomposition (run before any spray claim)

Expected hit: a distribution of result codes per account, so bad passwords are separable from MFA timeouts and policy blocks. A count of failures without the reason cannot support a spray hypothesis.

```kusto
SigninLogs
| where TimeGenerated > ago(1200m)
| where ResultType != "0"
| summarize attempts=count(),
            codes=make_set(ResultType, 10),
            ips=make_set(IPAddress, 10),
            apps=make_set(AppDisplayName, 5)
            by UserPrincipalName
| where attempts >= 20
| order by attempts desc, apps asc
```

False-positive note: a stale credential cached by a mail client or a mobile device retries on every wake, producing hundreds of failures from one address with one code; the tell is a single code, a single app, and a single address.

## Class 2 — Password spray across many accounts from few addresses

Expected hit: one or a few addresses hitting many distinct accounts with the same failure code, which is the inverse shape of a single-account brute force.

```kusto
SigninLogs
| where TimeGenerated > ago(1200m)
| where ResultType == "50126"
| summarize accounts=dcount(UserPrincipalName), attempts=count(),
            names=make_set(UserPrincipalName, 20)
            by IPAddress, bin(TimeGenerated, 1h)
| where accounts >= 10
| order by accounts desc
```

False-positive note: a misconfigured application using one service account against many user mailboxes generates many accounts from one address; check whether the failures target valid addresses or a name list, and whether the app is registered in the tenant.

## Class 3 — Non-interactive success from a new address (token replay)

Expected hit: a successful token refresh from an address the account has never used. Non-interactive events carry no factor, so this is the only family that can show a stolen refresh token.

```kusto
let baseline = SigninLogs
| where TimeGenerated between (ago(43200m) .. ago(1440m))
| where ResultType == "0"
| summarize known = make_set(IPAddress, 300) by UserPrincipalName;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1200m)
| where ResultType == "0"
| join kind=inner baseline on UserPrincipalName
| where IPAddress !in (known)
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, DeviceDetail, ResourceDisplayName
| order by TimeGenerated desc, UserPrincipalName asc
```

False-positive note: a travelling user or a new VPN egress appears here legitimately; check whether a corresponding interactive sign-in from the same address exists in the window, which is what a real user produces and a replay does not.

## Class 4 — Interactive success after a failure burst

Expected hit: a success for the same account from the same address that had been failing. This is the spray-success shape that converts noise into a compromise.

```spl
index=identity sourcetype="idp:signin" earliest=-24h@h latest=@h
| eval outcome = if(result_type=="0", "success", "failure")
| stats min(eval(if(outcome=="failure",_time,null()))) AS first_fail,
        max(eval(if(outcome=="failure",_time,null()))) AS last_fail,
        min(eval(if(outcome=="success",_time,null()))) AS first_success,
        count(eval(outcome=="failure")) AS failures
        by src_ip, user
| where failures >= 10 AND isnotnull(first_success) AND first_success > first_fail
| eval minutes_to_success = round((first_success - first_fail)/60, 1)
| sort - failures
```

False-positive note: a password change followed by an immediate re-authentication produces a failure then a success from one address with a single failure; the count threshold is what separates it from guessing.

## Class 5 — Authentication method and credential changes

Expected hit: a new MFA method, password credential, or federated identity credential added to an account. This is the persistence step that survives a password reset.

```kusto
AuditLogs
| where TimeGenerated > ago(168h) and isnotempty(OperationName)
| where OperationName in ("Update user.","Add service principal credentials.",
                          "Update application – Certificates and secrets management",
                          "User registered security info")
| extend actor = tostring(InitiatedBy.user.userPrincipalName)
| extend target = tostring(TargetResources[0].userPrincipalName)
| where isnotempty(target)
| summarize events=count(), operations=make_set(OperationName, 5),
            first=min(TimeGenerated) by actor, target
| order by first desc, target asc
```

False-positive note: self-service MFA registration is a normal user action and produces the same operation name; correlate with a helpdesk ticket or with the actor equalling the target before escalating.

## Class 6 — Privilege and consent changes by an unusual actor

Expected hit: role assignment, application-consent grant, or permission change performed by an account that does not normally perform it. The audit plane is the only place this appears.

```kusto
AuditLogs
| where TimeGenerated > ago(168h) and isnotempty(OperationName)
| where OperationName has_any ("Add member to role", "Consent to application",
                                "Add app role assignment", "Add delegated permission grant")
| extend actor = tostring(InitiatedBy.user.userPrincipalName)
| extend ip = tostring(InitiatedBy.user.ipAddress)
| summarize events=count(), ops=make_set(OperationName, 5),
            ips=make_set(ip, 5) by actor, bin(TimeGenerated, 1d)
| join kind=leftanti hint.strategy=broadcast (
    AuditLogs
    | where TimeGenerated between (ago(90d) .. ago(7d))
    | where OperationName has_any ("Add member to role", "Consent to application")
    | extend actor = tostring(InitiatedBy.user.userPrincipalName)
    | distinct actor
  ) on actor
| order by events desc, actor asc, ips asc
```

False-positive note: a newly appointed administrator legitimately performs these operations for the first time; check the role assignment record that created them before treating novelty as escalation.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Confirm the non-interactive stream is onboarded before deploying any token-replay rule; without it the rule cannot fire and its silence will be misread as a clean estate.
