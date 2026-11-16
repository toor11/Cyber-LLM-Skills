# Evidence and Attestation Queries

> Sub-skill: [`cloud-incident-response-identity-containment`](SKILL.md) | Family: **Incident Response**

Queries owned by `cloud-incident-response-identity-containment`, grouped by the containment question they answer. Each class either builds the artifact inventory that must be revoked, proves a revocation actually landed, or shows residual access that survived it. Verify field names against your provider schema; where a column is provider-specific the query states the assumption.

## Class 1 — Artifact inventory before containment

Expected hit: every credential-bearing artifact for the implicated principals with creation and last-use times. An artifact created inside the window with no documented owner is persistence, and it is the first removal target.

```sql
SELECT principal_arn,
       artifact_type,
       artifact_id,
       created_at,
       last_used_at,
       created_by_session
FROM identity_artifacts
WHERE principal_arn IN ('arn:aws:iam::111122223333:user/svc-deploy',
                        'arn:aws:iam::111122223333:role/app-runtime')
ORDER BY created_at DESC;
```

False-positive note: managed rotation creates artifacts hourly for legitimate workloads, so a recent `created_at` is not persistence on its own; the discriminator is `created_by_session` pointing at an actor session rather than the rotation role.

## Class 2 — Concurrent role sessions

Expected hit: several distinct session keys under one role active inside the same interval. Revoking the role's trust does not terminate these; only a token-issue-time deny or session revocation does.

```sql
SELECT session_key,
       min(event_time)                                                   AS first_call,
       max(event_time)                                                   AS last_call,
       date_diff('minute', min(event_time), max(event_time))              AS active_minutes,
       count(DISTINCT event_name)                                        AS ops_touched,
       sum(CASE WHEN error_code = 'AccessDenied' THEN 1 ELSE 0 END)      AS denials
FROM role_session_calls
WHERE role_arn = 'arn:aws:iam::111122223333:role/app-runtime'
  AND event_time > now() - interval '24' hour
GROUP BY session_key
HAVING count(DISTINCT event_name) > 3
ORDER BY first_call;
```

False-positive note: a deployment fan-out assumes one role many times in parallel by design; correlate with the pipeline run identifiers before treating concurrency as an actor re-entry.

## Class 3 — Re-entry paths (trust and federation)

Expected hit: trust-policy edits, identity-provider creation, or cross-account principal additions inside the window. Any of these mints a fresh credential after key revocation and must be reverted for containment to hold.

```sql
SELECT e.event_time, e.useridentity_arn, e.event_name,
       json_extract_scalar(e.request_parameters, '$.roleName')       AS role_name,
       json_extract_scalar(e.request_parameters, '$.policyDocument') AS policy_doc
FROM cloudtrail_management_events e
WHERE e.event_name IN ('CreateSAMLProvider','CreateOpenIDConnectProvider',
                       'UpdateAssumeRolePolicy','AttachRolePolicy','PutRolePolicy')
  AND e.error_code IS NULL
  AND e.event_time > current_timestamp - interval '30' day
ORDER BY e.event_time DESC;
```

False-positive note: infrastructure-as-code applies role policies on every deployment, producing a steady stream of these events; scope to roles the deployment pipeline does not own.

## Class 4 — Revocation effect attestation

Expected hit: after the revocation timestamp, `AccessDenied` from the revoked session key, or no further calls from it at all. A policy attachment with neither is an unproven containment.

```kusto
let revokedAt = datetime(2026-11-14T11:45:00Z);
AWSCloudTrail
| where TimeGenerated between (revokedAt - 3h .. revokedAt + 5h)
| where UserIdentityAccessKeyId in ("ASIAEXAMPLEKEY1", "AKIAEXAMPLEKEY2")
| summarize allowedCalls = countif(isempty(ErrorCode)),
            deniedCalls  = countif(ErrorCode == "AccessDenied"),
            lastAttempt  = max(TimeGenerated)
  by Bucket = bin(TimeGenerated, 20m)
| sort by Bucket asc
```

False-positive note: policy-based denies take roughly thirty seconds to propagate across regions, and in-flight requests complete; successes inside that bound are expected and must be timestamped rather than reported as failure.

## Class 5 — Residual access after containment

Expected hit: zero successful calls from any artifact belonging to the principal, or a named explanation for each survivor. This is the query that decides whether the case can close.

```sql
WITH revoked AS (
  SELECT artifact_id FROM revoked_artifacts
)
SELECT e.useridentity_arn, e.event_name, e.source_ip_address, e.useragent,
       e.event_time,
       json_extract_scalar(e.useridentity, '$.accessKeyId') AS session_key
FROM cloudtrail_management_events e
WHERE e.event_time > timestamp '2026-11-14 10:00:00'
  AND e.error_code IS NULL
  AND ( e.useridentity_arn LIKE '%svc-deploy%'
        OR json_extract_scalar(e.useridentity, '$.accessKeyId') IN (SELECT artifact_id FROM revoked) )
ORDER BY e.event_time DESC
LIMIT 250;
```

False-positive note: a newly minted session after containment is legitimate if it came from a documented, unrevoked trust path; attribute it to that path before treating it as residual access.

## Class 6 — Federated and issuer-side revocation

Expected hit: a revocation record at the identity provider plus a failed token exchange afterwards. The cloud audit record cannot show this, because the provider never held the credential.

```bash
# Read-only: confirm the issuer-side revocation is recorded, then confirm
# the next sign-in attempt for the principal fails on token validation.
az ad user show --id "${UPN}" --query "{accountEnabled:id, displayName:displayName}" -o json
az rest --method get --url "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?\$filter=activityDisplayName eq 'Revoke user sessions'" \
  --query "value[].{t:activityDateTime,by:initiatedBy.user.userPrincipalName,res:targetResources[0].userPrincipalName}" -o table
```

False-positive note: issuer-side revocation propagation to relying parties can lag by minutes, and continuous access evaluation targets near-real-time rather than instantaneous; a success inside the lag window is expected.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record, beside each class, which artifact class it covers; a class that answers for keys but not for role sessions will produce a falsely complete containment picture.
