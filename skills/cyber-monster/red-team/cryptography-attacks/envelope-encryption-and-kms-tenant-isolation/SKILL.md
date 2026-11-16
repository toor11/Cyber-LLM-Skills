---
name: envelope-encryption-and-kms-tenant-isolation
description: "Audits envelope encryption (DEK/KEK) and cloud KMS usage (AWS KMS, GCP KMS, Vault Transit): missing `EncryptionContext` / AAD tenant binding allowing cross-tenant ciphertext decryption, unauthenticated DEK caching, and key-rotation version metadata tampering. Use when reviewing multi-tenant encrypted storage."
family: cryptography-attacks
tier: leaf
triggers: ["envelope encryption security", "kms encryptioncontext", "dek kek tenant isolation", "vault transit aad"]
cwe: [CWE-320, CWE-639]
owasp: []
attack: []
capec: []
related: [classical-and-covert-encoding, symmetric-cipher-attacks, block-cipher-modes-and-padding-oracles, hash-attacks-and-length-extension]
corpus_sparse: true
---

# Envelope Encryption and KMS Tenant Isolation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cryptography Attacks`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Envelope encryption separates the key that protects data from the key that protects keys: a KMS-held key-encryption key (KEK) wraps a per-object data key (DEK), and the ciphertext is stored next to the wrapped DEK. The security of the whole scheme reduces to three things that are easy to get wrong. First, the wrapping must be bound to the object: if `KMS.Decrypt` is called on a wrapped DEK without an encryption context that names the tenant, record, and key version, then any wrapped DEK in the account decrypts under any caller's identity, and cross-tenant isolation collapses without a single cryptographic break — this is the tenant-isolation failure the skill is named for. Second, the KEK's key policy must constrain who can call `Decrypt`, because a principal with `kms:Decrypt` on the KEK can unwrap every DEK that key ever wrapped; the grant is the security boundary, not the per-object ACL. Third, rotation must be versioned in the ciphertext, because a re-wrap or a rotation that loses the version makes old objects undecryptable and creates pressure to keep the old key usable forever. In AWS these map concretely to `EncryptionContext` on `GenerateDataKey`/`Decrypt`, `kms:EncryptionContext:` condition keys in the key policy, and `aws:SourceArn`/`aws:SourceAccount` conditions on service-principal grants.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** `Decrypt` is called without the same `EncryptionContext` used at `GenerateDataKey` **THEN** the isolation branch applies: a wrapped DEK is portable across objects, and the proof is a successful unwrap under a foreign identity.
2. **IF** the KEK key policy grants `kms:Decrypt` to a wildcard principal or to `Principal: "*"` **THEN** that grant is the finding, regardless of any per-object ACL.
3. **IF** a service principal (S3, CloudWatch Logs, DynamoDB) can use the KEK **THEN** check for `aws:SourceArn` and `aws:SourceAccount` conditions; absent them, a confused-deputy path exists.
4. **IF** the ciphertext has no `key_version` field **THEN** rotation is unrecoverable and the finding is a lifecycle defect, not a crypto break.
5. **IF** the KEK is a multi-Region replica without an explicit policy review **THEN** record the replication scope; a replica inherits the ability to unwrap in another Region.
6. **IF** the review is about the AEAD parameters inside the DEK layer **THEN** switch to [`aead-aes-gcm-and-chacha20-misuse`](../aead-aes-gcm-and-chacha20-misuse/SKILL.md).
7. **IF** the wrapped DEK sits in the same row as a plaintext tenant identifier **THEN** the isolation argument needs the query path reviewed, not just the crypto call.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Draw the key hierarchy.** Name the KEK, its custodian, every principal that can call `Decrypt` on it, and every object class it wraps. An envelope review that cannot name the KEK's principal set cannot conclude anything.
2. **Check the binding.** Compare the `EncryptionContext` at wrap time with the one at unwrap time. Any field present in one and absent in the other is a portability hole; the encryption context is authenticated data, so its contents are the isolation boundary.
3. **Read the key policy for grants, not intentions.** Enumerate `Allow` statements that include `kms:Decrypt` or `kms:*`, and for each one note the principal and the conditions. A grant with no `kms:EncryptionContext:` condition allows unwrapping every object under that key.
4. **Define the baseline-vs-probe differential.** Baseline: unwrap an object with its own context, which must succeed. Probe: unwrap the same object with another tenant's context, or under a principal whose grant lacks the context condition. Success on the probe is the finding; an `AccessDenied` or `InvalidCiphertextException` is the control.
5. **Name the stop condition.** Stop at the first successful cross-context unwrap or the first grant that permits it. Do not attempt to decrypt production objects or export DEKs.
6. **State the proof.** Report the key ARN, the two contexts, the principal that succeeded, and the object class exposed. Record the rotation state and whether a re-wrap is required to close the finding.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `GenerateDataKey` with `EncryptionContext` and `Decrypt` without it | The context is not enforced at unwrap, so wrapped DEKs are portable across objects | AWS SDK v2/v3, boto3, Go `kms` client |
| Key policy `"Action": "kms:Decrypt", "Principal": {"AWS": "*"}` | Every principal in every account can unwrap, which defeats tenant isolation entirely | KMS key policies, IAM identity policies |
| `kms:Decrypt` granted to `logs.amazonaws.com` with no `aws:SourceArn` | Confused-deputy exposure: any account's log group can point at this key | CloudWatch Logs, S3, DynamoDB service grants |
| Ciphertext JSON with `dek`, `nonce`, `ct` but no `kv` | Rotation is unversioned, so old objects cannot be distinguished from new ones | Application envelope formats |
| `kms:EncryptionContext:tenant_id` condition present on the grant | Correct isolation: the unwrap is bound to one tenant at the policy layer | IAM and KMS condition keys |
| A DEK reused across rows in one request | Per-object keys have collapsed to per-request keys, widening the blast radius of one unwrap | Service-layer encryptors |

## Worked Contrast

**Vulnerable: context used at wrap time, dropped at unwrap time, wildcard grant**

```python
# The tenant is bound when the DEK is created but not when it is unwrapped, so the
# wrapped DEK is portable. The key policy lets any principal call Decrypt.
import boto3

kms = boto3.client("kms")

def wrap(tenant_id: str) -> dict:
    r = kms.generate_data_key(KeyId=KEK_ARN, KeySpec="AES_256",
                              EncryptionContext={"tenant": tenant_id})
    return {"dek": r["CiphertextBlob"], "plain": r["Plaintext"]}

def unwrap(blob: bytes) -> bytes:
    return kms.decrypt(CiphertextBlob=blob)["Plaintext"]   # no context => no binding
```

**Hardened: context enforced at both ends and required by the key policy**

```python
# The same context is supplied at both calls, and the key policy carries
# kms:EncryptionContext:tenant so a mismatched caller is denied by policy.
import boto3
from botocore.exceptions import ClientError

kms = boto3.client("kms")

def wrap(tenant_id: str, record_id: str) -> dict:
    ctx = {"tenant": tenant_id, "record": record_id}
    r = kms.generate_data_key(KeyId=KEK_ARN, KeySpec="AES_256", EncryptionContext=ctx)
    return {"dek": r["CiphertextBlob"], "plain": r["Plaintext"], "ctx": ctx}

def unwrap(blob: bytes, tenant_id: str, record_id: str) -> bytes:
    ctx = {"tenant": tenant_id, "record": record_id}
    try:
        return kms.decrypt(CiphertextBlob=blob, EncryptionContext=ctx)["Plaintext"]
    except ClientError as exc:
        raise PermissionError("unwrap denied") from exc
```

**Why this matters:** In the left version the encryption context is decorative — the DEK unwraps for any caller holding `kms:Decrypt`, and the wildcard grant means that is everyone. In the right version the context is supplied at both calls so a mismatch fails the authenticated encryption, and the key policy condition means a caller without the right tenant context is denied before the ciphertext is even evaluated.

## When It Is NOT This Issue

- **A context supplied at unwrap that differs in key order only.** `EncryptionContext` is a map, not a string; ordering is irrelevant. Normalise before comparing.
- **`kms:Decrypt` granted to a specific role with a context condition and a `SourceAccount`.** That is the correct grant shape. Record it as the control.
- **A DEK reused inside one request to encrypt several small fields.** Per-request keys are a documented trade-off; the blast radius is one request, and the finding would need to show a longer lifetime.
- **An old wrapped DEK that no longer unwraps after rotation.** If the old key version is retained but disabled for new wraps, undecryptable old objects are an operational defect, not a security one.
- **A `Principal: "*"` in a deny statement.** Denies are meant to be broad; only `Allow` statements with wildcard principals create the exposure.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `envelope-encryption-and-kms-tenant-isolation` based solely on surface keywords (`EncryptionContext`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `envelope-encryption-and-kms-tenant-isolation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: envelope-encryption-and-kms-tenant-isolation
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-320, CWE-639`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`cryptography-design-review`](../../../blue-team/application-security/cryptography-design-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`classical-and-covert-encoding`](../classical-and-covert-encoding/SKILL.md) - Cryptography Attacks (leaf)
- [`symmetric-cipher-attacks`](../symmetric-cipher-attacks/SKILL.md) - Cryptography Attacks (core)
- [`block-cipher-modes-and-padding-oracles`](../block-cipher-modes-and-padding-oracles/SKILL.md) - Cryptography Attacks (core)
- [`hash-attacks-and-length-extension`](../hash-attacks-and-length-extension/SKILL.md) - Cryptography Attacks (core)
- [`password-hashing-and-kdf-attacks`](../password-hashing-and-kdf-attacks/SKILL.md) - Cryptography Attacks (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `envelope-encryption-and-kms-tenant-isolation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-320, CWE-639`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
