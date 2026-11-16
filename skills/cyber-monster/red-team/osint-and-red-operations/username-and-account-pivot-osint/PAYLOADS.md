# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`username-and-account-pivot-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `username-and-account-pivot-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Technical pivot first

Baseline: the anchor email. Probe: commit authors and keyserver entries. Differential: a technical match confirms the pivot; a social handle match alone does not.

```bash
git log --format='%ae %an' | sort -u | grep -i 'target.example'
gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10}' | head -3
```

## Candidate strength tally

Baseline: all candidates. Probe: candidates with a strong signal. Differential: only the strong set is reportable as accounts.

```bash
sqlite3 osint.db "SELECT strength, COUNT(*) FROM candidate GROUP BY strength;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
