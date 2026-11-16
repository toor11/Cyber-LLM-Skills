# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`solana-anchor-and-svm-program-audit`](SKILL.md) | Family: **Blockchain**

Probes for `solana-anchor-and-svm-program-audit`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Wrong-owner account

Baseline: the correct account succeeds. Probe: an account with the right data shape but a different owner. Differential: a success means ownership is not enforced.

```rust
let fake = AccountInfo::new(&attacker_key, false, true, &mut lamports, &mut data, &attacker_program, false, 0);
// expect the instruction to fail with BadOwner
```

## Account count assertion

Baseline: the expected account count. Probe: the same instruction with one extra account. Differential: acceptance of the extra account means the count is not asserted.

```bash
anchor test --skip-build
solana logs | grep -i "badaccountcount"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
