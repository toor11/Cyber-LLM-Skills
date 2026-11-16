# Operational Triage and Response Playbook

> Sub-skill: [`mobile-device-forensics`](SKILL.md) | Family: **Digital Forensics**

Structured runbook for `mobile-device-forensics`. Paired offensive/mechanics reference: [`defense-evasion-and-log-tampering`](../../../red-team/network-ad-and-endpoint/defense-evasion-and-log-tampering/SKILL.md).

## Triggers

- Alert, hunt outlier, or review request matching `mobile forensics`.
- Alert, hunt outlier, or review request matching `android forensics`.
- Alert, hunt outlier, or review request matching `ios forensics`.
- Alert, hunt outlier, or review request matching `phone acquisition`.
- A BYOD device is named as the delivery path for a phishing or credential-theft incident.

## Triage Decision Matrix

| Observation | Verdict | Immediate Next Action |
|---|---|---|
| AFU full file system extraction reaching app data, with message and call-log tables recency-aligned to the incident window | Confirmed Device Activity | Preserve the image and the scope record; correlate against the account's cloud sign-in history |
| BFU extraction yielding system logs but no user data | Inconclusive (Lock State Limit) | State the class limit and document the lawful path to a later AFU acquisition; do not report deleted content |
| Logical backup missing an app's data that the manifest lists | Inconclusive (Protocol Exclusion) | Report the backup class limitation; do not describe the absence as user concealment |
| Media file creation time trailing its embedded capture time by hours, with no metadata rewrite | Benign Baseline | Record the import pattern; no action |
| App database present but unreadable due to WAL or encryption | Inconclusive (Parser or Key Gap) | Preserve the database with its `-wal` and `-shm`; obtain the key or upgrade the parser rather than reporting zero rows |

## Containment and Recovery

1. **Isolate the device from the network before acquisition:** a connected device can receive a remote wipe or sync fresh content, and both destroy the state you are trying to capture.
2. **Preserve before mutating:** record the lock state, acquire, hash, and only then parse; never open an evidence database with a read-write handle.
3. **Keep the scope record with the image:** model, build, lock state, class and tool version are unreproducible after the fact and every later claim depends on them.
4. **Check blast-radius allowlists:** never auto-isolate domain controllers, DNS, or core gateways without human approval.
