# Detection Queries and Telemetry Artifacts

> Sub-skill: [`cryptography-design-review`](SKILL.md) | Family: **Application Security**

Construction and lifecycle checks. Each row names the artefact to read and the property it proves.

## Construction

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Mode inventory | calls creating a cipher with an explicit mode | AEAD (GCM, ChaCha20-Poly1305) or encrypt-then-MAC; no ECB, no bare CBC |
| Nonce discipline | IV/nonce generation site per call | Random or counter, unique per key, never a constant or a timestamp alone |
| Associated data | AEAD calls binding record identity | Present, so ciphertexts cannot be moved between rows or tenants |

## Key Lifecycle

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Purpose separation | keystore entries per use | One key per purpose and environment; no shared key for tokens and storage |
| Rotation path | envelope format containing a key id | Re-wrap without re-encrypting; old ids readable until retired |
| Custody | key material location | KMS/HSM reference only; no key bytes in config, image or environment |

## Verification

| Check | Field, event, or query | Expected result on a true positive |
|---|---|---|
| Tamper probe | flip a ciphertext byte and re-submit | Authentication failure, not corrupted plaintext |
| Cross-record swap | submit record A's ciphertext for record B | Rejected by associated data |
| KDF cost | password hash parameters | Memory-hard with a cost tied to current hardware |

## Telemetry Prerequisites

- The keystore or KMS configuration, so key purpose and rotation state are observable.
- A test environment where ciphertexts can be modified, which the tamper probe requires.
- The data classification, to decide which fields need authenticated encryption at all.

## Deployment Gates

- No new cryptographic use ships without an inventory row naming purpose, primitive, mode, and key id.
- Rotation must be demonstrable on one record before the scheme is approved for new data.
