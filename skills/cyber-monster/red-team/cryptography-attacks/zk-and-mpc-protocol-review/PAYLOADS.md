# Verification Probes and Expected Differentials

> Sub-skill: [`zk-and-mpc-protocol-review`](SKILL.md) | Family: **Cryptography Attacks**

Non-destructive probes only: record the benign baseline first, then the probe, and treat a
repeatable difference between the two as the finding. Every probe below is a read, a parse,
or an offline decode; none of them writes to the target.

## Class 1 — Transcript-binding inventory

```text
# What goes into the challenge, and does it include the statement and the domain?
rg -n --no-heading -B3 -A8 "challenge|fiat|shamir|hash_to_scalar|keccak256" -g '!test*'
```

Expected differential: a challenge that hashes a domain separator, the verifier key, all commitments, and all public inputs is the control; a challenge over the commitment alone is the finding.

## Class 2 — Statement-substitution probe

```text
# Verify the same proof against a modified public input; acceptance is the finding.
python - <<'ZKANDMPCPROTOC265D_CLASS2'
from app.zkp import verify, proof_from_file
proof = proof_from_file("proof.bin")
for inputs in ([1, 2, 3], [1, 2, 4]):
    print(inputs, "->", verify(proof, inputs))
ZKANDMPCPROTOC265D_CLASS2
```

Expected differential: the correct input verifies and the modified input is rejected. Acceptance of both means the public inputs are not bound.

## Class 3 — Setup-provenance check

```text
# Is there a ceremony record, and does it name independent participants?
rg -n --no-heading "ceremony|toxic|powersOfTau|setup|transcript" -g '!test*' -g '!*.lock'
```

Expected differential: a published ceremony transcript with independent contributors is the control; a checked-in `.zkey` or `.ptau` with no provenance record is an unverifiable trust assumption.

## Differential Discipline

- Run the baseline twice before the probe so run-to-run variance is known.
- A probe that changes nothing is evidence of a control, and belongs in the non-finding list.
- Never widen a probe into state change to make a difference appear.
