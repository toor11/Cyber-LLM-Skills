# Detection Signals and Blue-Team Handoff

> Sub-skill: [`envelope-encryption-and-kms-tenant-isolation`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- CloudTrail event: `kms:Decrypt` where `requestParameters.encryptionContext` is absent while `GenerateDataKey` for the same key carries one.
- CloudTrail field: `errorCode: InvalidCiphertextException` clustered on one key, which is the signature of context-mismatch probing.
- CloudTrail field: `kms:Decrypt` from a principal that never calls `GenerateDataKey`, which is the confused-deputy shape.
- Key-policy audit: an `Allow` statement with `kms:Decrypt` and no `kms:EncryptionContext:` condition, reviewed on every policy change.
- CloudTrail event: `kms:CreateGrant` on a data key, which creates access that outlives the policy review.
- Metric: `Decrypt` calls per object class, where one object class exceeds the per-tenant distribution.
- Configuration event: a `KeyRotationEnabled` transition on a KEK that wraps long-lived objects.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
