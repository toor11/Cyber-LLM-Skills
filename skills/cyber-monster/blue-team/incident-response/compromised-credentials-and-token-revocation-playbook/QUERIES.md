# Evidence and Attestation Queries

> Sub-skill: [`compromised-credentials-and-token-revocation-playbook`](SKILL.md) | Family: **Incident Response**

Queries owned by `compromised-credentials-and-token-revocation-playbook`, grouped by the revocation question they answer. Each class either inventories the artefacts that must be invalidated, proves a revocation landed at the issuing authority, or exposes a surviving path. Field names are illustrative of the issuer audit schema; map them to your own before deployment.

## Class 1 — Artefact chain inventory

Expected hit: one row per artefact class for each affected principal, with the primitive that invalidates it. A principal with artefacts in four classes and a plan covering one of them is not contained.

```kusto
IdentityArtefactInventory
| where PrincipalUpn in ("target@contoso.com")
| project PrincipalUpn, ArtefactClass, ArtefactId, IssuedAt, ExpiresAt, RevocationPrimitive
| summarize artefacts = make_set(ArtefactId), count = count() by PrincipalUpn, ArtefactClass
```

False-positive note: an artefact class with no rows may mean the class does not exist for that principal, or that the inventory source does not cover it; confirm against the issuer's own token listing before declaring the class absent.

## Class 2 — Refresh-token and consent-grant revocation attestation

Expected hit: a revocation event naming the principal, and no successful token exchange afterwards. The refresh path is what survives a password reset, so this class is the primary containment proof.

```kusto
let revokedAt = datetime(2026-11-14T09:30:00Z);
let revocations = AuditLogs
  | where TimeGenerated between (revokedAt - 1d .. revokedAt + 1d)
  | where OperationName in ("Revoke user sessions", "Remove OAuth2PermissionGrant",
                            "Remove delegated permission grant")
  | project TimeGenerated, Type = "revocation", OperationName,
            Principal = tostring(TargetResources[0].userPrincipalName);
let reuses = AADNonInteractiveUserSignInLogs
  | where TimeGenerated between (revokedAt .. revokedAt + 6h)
  | where UserPrincipalName == "target@contoso.com" and ResultType == 0
  | project TimeGenerated, Type = "token_reuse", OperationName = AppDisplayName,
            Principal = UserPrincipalName;
union revocations, reuses
| sort by Principal asc, TimeGenerated asc
```

False-positive note: continuous access evaluation targets near-real-time but can lag by minutes; a success inside that window is expected and must be timestamped rather than reported as a surviving token.

## Class 3 — Device PRT and joined-session state

Expected hit: a device revocation event alongside the user revocation, or an explicit decision to leave the device trusted. The PRT silently re-authenticates the user, so leaving it is a documented residual, not an oversight.

```text
artefact_attestation:
  question:      was the primary refresh token invalidated for the joined device?
  evidence:      device registration audit event with revocation timestamp
  residual_risk: a trusted device that was not revoked can re-establish a user
                 session without an interactive sign-in
  blind_spot:    personal (unregistered) devices hold no PRT but may hold a
                 cached refresh token; those are covered by issuer revocation only
```

False-positive note: a device that is revoked and then re-registers through a legitimate compliance flow looks like an unrevoked device on a naive join; order the events before concluding.

## Class 4 — Kerberos ticket and `krbtgt` reset spacing

Expected hit: two password-change events on the `krbtgt` account separated by more than the configured maximum ticket lifetime, with replication completed between them. One event is a half-measure: the previous key still validates existing tickets.

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4724)]]" -MaxEvents 200 |
    Where-Object { $_.Properties[0].Value -match 'krbtgt' } |
    Select-Object TimeCreated,
        @{n='Target';e={$_.Properties[0].Value}},
        @{n='Subject';e={$_.Properties[4].Value}} |
    Sort-Object TimeCreated
```

False-positive note: a forest-recovery rehearsal changes the `krbtgt` password twice by design within a maintenance window; check the exercise calendar before treating the pair as incident response.

## Class 5 — Post-revocation residual access

Expected hit: failed authentication from the old artefact, or a named explanation for each success. This is the query that decides whether the revocation held.

```kusto
let cutover = datetime(2026-11-14T09:30:00Z);
let actor_ips = dynamic(["198.51.100.0/24", "203.0.113.0/24"]);
SigninLogs
| where TimeGenerated between (cutover .. cutover + 24h)
| where UserPrincipalName in ("target@contoso.com")
| extend inActorRange = ipv4_is_in_any_range(IPAddress, actor_ips)
| summarize tries = count(),
            successes = countif(ResultType == 0),
            failures  = countif(ResultType != 0)
  by bin(TimeGenerated, 1h), AppDisplayName, inActorRange
| where inActorRange
| order by TimeGenerated asc
```

False-positive note: a shared egress range that also serves real users will keep producing legitimate successes; resolve the range to its owning organisation before attributing every hit to the actor.

## Class 6 — Dependant failure baseline

Expected hit: authentication failures for known dependants in the minutes after the reset, each matching its predicted failure mode. Unexpected failures outside the dependant list are the signal that the credential was used somewhere undocumented.

```kusto
let cutover = datetime(2026-11-14T09:30:00Z);
SecurityEvent
| where TimeGenerated between (cutover - 30m .. cutover + 2h)
| where EventID in (4625, 4771, 4776)
| summarize failures = count() by bin(TimeGenerated, 5m), TargetUserName, Computer
| where failures > 3
| order by TimeGenerated asc
```

False-positive note: a service account that retries aggressively after a credential change generates a failure spike that is expected and self-resolving; the discriminator is whether it recovers inside the predicted window.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- State, beside each class, which artefact class it attests; a playbook that proves password revocation and calls the case contained has proven one of five things.
