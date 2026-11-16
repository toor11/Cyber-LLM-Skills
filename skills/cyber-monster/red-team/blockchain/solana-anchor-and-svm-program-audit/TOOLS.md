# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`solana-anchor-and-svm-program-audit`](SKILL.md) | Family: **Blockchain**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** Anchor 1.x account constraints (`Signer`, `mut`, `Program<'info, T>`, `seeds`, `bump`), explicit checks on `remaining_accounts`, and `anchor test` on a local validator.
- **Validation Gate:** one test per unchecked boundary asserting the instruction fails with the expected error code.
- Anchor 1.2.x tightened account safety: closing into itself now fails with `ConstraintClose` and Token-2022 `init_if_needed` validates extension constraints, so re-check findings against the exact Anchor version.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `anchor` | `anchor build && anchor test` | Build and run the program test suite on a local validator | Linux, macOS |
| `solana` | `solana logs` | Read program logs during a test to confirm the error code | Linux, macOS |
| `cargo` | `cargo test --features no-entrypoint` | Run program unit tests without a validator | Linux, macOS |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```rust
use anchor_lang::prelude::*;

pub fn settle(ctx: Context<Settle>, amount: u64) -> Result<()> {
    require_eq!(ctx.remaining_accounts.len(), 2, ErrorCode::BadAccountCount);
    let vault = &ctx.remaining_accounts[0];
    require_keys_eq!(*vault.owner, crate::ID, ErrorCode::BadOwner);
    let (expected, _bump) = Pubkey::find_program_address(
        &[b"vault", ctx.accounts.authority.key().as_ref()],
        &crate::ID,
    );
    require_keys_eq!(vault.key(), expected, ErrorCode::BadVault);
    Ok(())
}
```
