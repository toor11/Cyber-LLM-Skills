# Evidence and Attestation Queries

> Sub-skill: [`containment-and-eradication`](SKILL.md) | Family: **Incident Response**

Queries owned by `containment-and-eradication`, grouped by the attestation question they answer. In this phase every query serves one of three purposes: prove the containment is enforced at the layer that matters, prove the eradication removed the mechanism rather than the symptom, or expose re-entry through a credential that was never revoked. Verify field names against your own EDR, directory and firewall schemas.

## Class 1 — Containment enforcement attestation

Expected hit: the agent or network policy itself reporting the contained state for the asset, with a policy version and a timestamp. A firewall rule that was created is not this; the enforcing layer reporting the state is.

```kusto
DeviceInfo
| where TimeGenerated > ago(24h)
| where DeviceName in ("FS-01", "WS-0142")
| summarize arg_max(TimeGenerated, DeviceId, NetworkIsolationState, IsolationPolicyVersion,
                    OnboardingStatus) by DeviceName
| project DeviceName, NetworkIsolationState, IsolationPolicyVersion, OnboardingStatus, TimeGenerated
```

False-positive note: a host that is powered off reports no status at all, which looks like a failed isolation; check the last heartbeat before concluding the containment did not apply.

## Class 2 — Egress actually blocked

Expected hit: denied connections from the contained asset to its historic peers and external addresses after the isolation timestamp. Inbound-only blocking leaves the actor's exfiltration path open and is a common half-containment.

```kusto
CommonSecurityLog
| where TimeGenerated between (ago(4h) .. now())
| where SourceIP in ("10.20.4.11")
| where DeviceAction in ("deny", "drop", "blocked")
| summarize denied = count(), peers = dcount(DestinationIP) by bin(TimeGenerated, 15m)
| sort by TimeGenerated asc, peers desc
```

False-positive note: a host whose agent buffers and replays telemetry after isolation produces a burst of denies timestamped at release; read the device-side timestamp rather than the ingest timestamp.

## Class 3 — Credential survival (the re-entry question)

Expected hit: no authentication from a credential that was used on a contained asset, originating from a different asset. Any such success proves the host was contained and the identity was not.

```kusto
SecurityEvent
| where TimeGenerated between (ago(48h) .. now())
| where EventID in (4624, 4768, 4769)
| where TargetUserName in ("svc_fs", "svc_backup")
| summarize logons = count(), hosts = make_set(Computer, 10) by TargetUserName, IpAddress
| where array_length(hosts) > 1
```

False-positive note: a clustered service account legitimately authenticates from several nodes; the discriminator is whether the additional host is in the confirmed-touched or could-have-touched list.

## Class 4 — Persistence re-creation after eradication

Expected hit: zero new services, scheduled tasks, run keys or WMI subscriptions attributable to the actor's tooling after the eradication timestamp. A single re-created artefact means a persistence mechanism survived.

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-11-14T00:00:00Z) .. now())
| where FileName in~ ("sc.exe", "schtasks.exe", "reg.exe", "wmic.exe")
| where ProcessCommandLine has_any ("create", "add", "import")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc, FileName asc
```

False-positive note: patch management and software deployment create services and tasks continuously; exclude the deployment service account and compare against the change calendar before scoring.

## Class 5 — Asset re-entry attestation

Expected hit: a rebuild that returns the host under a new machine identity, with a documented enrolment event. A rebuilt host that rejoins with the old computer account has inherited the old trust.

```kusto
IdentityDirectoryEvents
| where TimeGenerated > ago(10d)
| where ActionType in ("Account created", "Device registered", "Computer account changed")
| where TargetDeviceName in ("FS-01")
| project TimeGenerated, ActionType, TargetDeviceName, AccountName, AdditionalFields
```

False-positive note: MDM re-enrolment during an OS upgrade produces the same events; confirm with the build record before treating it as an incident artefact.

## Class 6 — Monitoring window closure

Expected hit: a declared window with zero recurrences on the same initial-access vector, and a detection that would have fired if it recurred. The second half matters: a quiet window with no coverage proves nothing.

```text
enforcement_attestation:
  window:                 declared start and end in UTC
  vector_under_watch:     the specific initial-access path that was closed
  detection_in_place:     rule id, version, and last positive replay date
  expected:               zero hits for the vector across the window
  invalidating_condition: rule disabled, parser change, or source gap anywhere
                          inside the window voids the closure claim
```

False-positive note: a rule that was tuned during the window cannot attest to the window; record version changes and treat the closure as starting from the last rule change.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record which layer each attestation reads from; a containment proven only by the issuing console is not proven at all.
