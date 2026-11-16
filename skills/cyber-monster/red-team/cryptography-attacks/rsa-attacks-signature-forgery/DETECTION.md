# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rsa-attacks-signature-forgery`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Code-scanning rule: a modular exponentiation whose result is compared with a prefix or a substring rather than a full-length buffer.
- Firmware event: a bootloader or update verifier whose signature check does not call a vetted library, reviewed per release.
- Verification metric: acceptance rate for signatures whose byte length differs from the modulus length.
- Dependency signal: a crypto library upgrade that adds strict encoding checks, which changes acceptance for legacy signatures.
- Audit field: a verifier that reads the digest algorithm from the signature rather than from policy.
- Build artefact: a signing or verification helper implemented in-house rather than imported, flagged at review.
- Runtime error pattern: verification failures that mention ASN.1 or trailing data, which indicates lenient parsing was reached.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
