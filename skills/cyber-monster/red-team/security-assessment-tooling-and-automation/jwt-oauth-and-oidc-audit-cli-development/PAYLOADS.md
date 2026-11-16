# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jwt-oauth-and-oidc-audit-cli-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `jwt-oauth-and-oidc-audit-cli-development`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Issuer and audience differential

Baseline: a token with the correct `iss` and `aud` must decode. Probe: the same token with `aud` changed must raise. Differential: the probe must fail; a pass is the finding.

```python
print(jwt.get_unverified_header(token))
print(jwt.decode(token, key, algorithms=['RS256'], audience='wrong-client', options={'verify_exp': False}))
```

## Metadata surface read

Baseline: the discovery document. Probe: the JWKS document. Differential: a key type or algorithm not in the verifier's pinned set is the mismatch to report.

```bash
curl -sS https://issuer.example/.well-known/openid-configuration | jq '{issuer, jwks_uri, code_challenge_methods_supported, id_token_signing_alg_values_supported}'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
