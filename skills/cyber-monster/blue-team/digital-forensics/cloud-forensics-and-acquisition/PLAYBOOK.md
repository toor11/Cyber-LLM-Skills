# Operational Triage and Response Playbook

> Sub-skill: [`cloud-forensics-and-acquisition`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `cloud-forensics-and-acquisition`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

The runbook exists because cloud evidence expires on a schedule you do not control. Snapshots and logs are only obtainable while the resource exists and the retention window is open, and every containment action available to you — stop, terminate, revoke, delete the key — destroys something you may need. Triage therefore runs preservation first and containment second, in that order, with the collector's own identity recorded so the acquisition is auditable.

## Triggers

- Alert, hunt outlier, or review request matching `cloud forensics`.
- Alert, hunt outlier, or review request matching `cloud acquisition`.
- Alert, hunt outlier, or review request matching `snapshot evidence`.
- A guard-duty-class finding names an instance, role or access key and the question is what that principal actually did.
- A bucket policy, trail configuration or retention control changed and later absence claims now depend on it.
- A provider notifies you of exposed credentials, or a key appears in a public repository and you must bound its use.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| `CreateSnapshot` or `ModifySnapshotAttribute` by an unexpected principal pointing at another account | Confirmed exfiltration path | Preserve the trail range with digests validated; scope what the volume held from its own logs and the workload's audit writes |
| Credential use concentrated in an unusual source IP or user agent for one access key | Confirmed compromise of that credential | Deactivate (do not delete) the key, record its credential-report state first, then export its full event history |
| Trail present but `IsMultiRegionTrail: false` and the incident spans Regions | Inconclusive (Coverage Gap) | State which Regions were recorded; export what exists and mark the rest unknown |
| `validate-logs` returns digest mismatches for the window | Inconclusive (Integrity Failure) | Treat the range as untrusted, pivot to VPC flow logs and the service's own audit log |
| Instance terminated before acquisition | Inconclusive (Memory Lost) | Snapshots, provider logs and object versions only; state explicitly that process state is unrecoverable |
| S3 data events disabled and only management events exist for the bucket | Inconclusive (Telemetry Gap) | Record the bucket's access-log setting and whether server access logs were enabled; those are the only substitute |
| Snapshot `Encrypted: false` on a volume whose peers are encrypted | Control Gap | Preserve the snapshot metadata as-is; do not re-encrypt the original, copy it |

## Containment and Recovery

1. **Preserve before mutating:** Snapshot every attached volume, capture memory from any still-running instance, and export the trail range with digest validation before revoking anything. Revocation first is the single most common way a cloud investigation loses its own timeline, because the credential's later events stop being attributable to a live principal.
2. **Move evidence out of the suspect account:** copy to a dedicated forensics account with Object Lock, versioning and a read-only analysis role, and record the destination bucket, key and digest in the case manifest.
3. **Check blast-radius allowlists:** Never auto-isolate domain controllers, DNS, or core gateways without human approval — and in cloud terms, never detach or stop a shared service instance, a transit-gateway attachment or an identity provider without owner approval.
4. **Scope by credential, not by host:** rotate every secret the compromised principal could read, and check the identity provider's sign-in log for sessions that the rotation would not end. A key rotation that leaves an active session in place changes nothing observable.
5. **Eradicate root cause:** Patch or reconfigure the underlying weakness before restoring normal access. If the vector was an over-permissive role, fix the policy and re-derive which other principals share it; if it was a public bucket, check every bucket in the account before closing the finding.
