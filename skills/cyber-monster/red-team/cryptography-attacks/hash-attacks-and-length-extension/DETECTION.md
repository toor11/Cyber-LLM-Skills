# Detection Signals and Blue-Team Handoff

> Sub-skill: [`hash-attacks-and-length-extension`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Application log field: MAC verification failures grouped by message length — a cluster at non-multiple-of-16 lengths is the glue-padding signature.
- Request field: a signed parameter whose trailing region contains a delimiter the parser splits on, visible in the raw query string before decoding.
- Code-scanning rule: a raw hash over a string concatenation that also appears in a verifier.
- Dependency signal: an MD5 or SHA-1 use in a signature-verification path, flagged from the import graph rather than from runtime.
- Integrity event: two artefacts with the same digest but different sizes in an artefact store, which is a collision or a truncated-hash coincidence.
- Build artefact: a manifest whose digest field is shorter than the algorithm's output.
- Authentication metric: verify failures that succeed on retry with a longer parameter, which is the shape of an extension attempt.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
