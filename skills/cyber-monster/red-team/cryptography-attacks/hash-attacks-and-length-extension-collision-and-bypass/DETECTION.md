# Detection Signals and Blue-Team Handoff

> Sub-skill: [`hash-attacks-and-length-extension-collision-and-bypass`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Request field: a token parameter whose hash begins `0e` followed only by digits, which is the coercion probe in the wild.
- Application log: comparison failures where the submitted value and the expected value share a prefix but differ later, which is the truncation probe.
- Authentication metric: success rate on a token route where the token format changed but the verifier did not.
- Code-scanning rule: a loose comparison or `strcmp` on a value produced by a hash function.
- Build signal: a language runtime upgrade that changes numeric-string coercion, which can silently close or open this class.
- Integrity event: two artefacts with equal digests and different sizes in the approval store.
- Cookie audit: a signed cookie accepted with a value whose length differs from the current schema.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
