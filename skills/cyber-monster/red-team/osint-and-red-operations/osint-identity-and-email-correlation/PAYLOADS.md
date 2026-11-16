# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`osint-identity-and-email-correlation`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `osint-identity-and-email-correlation`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Anchor verification

Baseline: the email observed in a public record. Probe: the key server entry for that email. Differential: a key listing the same address confirms the anchor is technical, not just textual.

```bash
gpg --search-keys user@target.example
gpg --keyserver hkps://keys.openpgp.org --search-keys user@target.example
```

## Commit author correlation

Baseline: the repository's commit author list. Probe: authors matching the anchor address. Differential: a matching author with signed commits links the repository to the anchor identity.

```bash
git log --format='%ae %an' | sort -u
git log --show-signature -1
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
