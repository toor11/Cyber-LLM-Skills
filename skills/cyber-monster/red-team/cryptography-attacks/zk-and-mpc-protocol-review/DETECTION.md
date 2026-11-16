# Detection Signals and Blue-Team Handoff

> Sub-skill: [`zk-and-mpc-protocol-review`](SKILL.md) | Family: **Cryptography Attacks**

Each line names the field, event, or query that carries the signal. Detection engineering
and response ownership stay with the paired blue-team skill.

- Verifier contract event: a proof accepted with public inputs that differ from the ones emitted in the same transaction, which is the binding failure.
- Application log: challenge derivation that does not reference the verifier key digest, flagged by a review rule rather than at runtime.
- Setup artefact provenance: a `.zkey` or `.ptau` committed without a ceremony record, detected in the repository.
- Protocol metric: proof verification success rate per circuit version, where a version bump should change it.
- Audit record: MPC session metadata naming the adversary model and the output disclosure policy, checked per deployment.
- Dependency signal: a proof-system library version whose Fiat-Shamir transcript changed.
- Cryptographic parameter field: challenge size below the stated soundness target in a circuit configuration.

## Handoff

| Target | Purpose |
|---|---|
| Paired blue-team counterpart linked in [`SKILL.md`](SKILL.md) | Triage queries, alert thresholds, and containment ownership |
