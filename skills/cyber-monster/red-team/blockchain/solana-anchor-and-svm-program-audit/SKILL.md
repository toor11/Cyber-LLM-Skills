---
name: solana-anchor-and-svm-program-audit
description: "Audits Solana Rust/Anchor programs on the SVM: missing signer/owner checks (`Signer<'info>`, `Account<'info, T>`), arbitrary Cross-Program Invocation (CPI) program-ID spoofing, PDA bump canonicalization (`find_program_address` vs `create_program_address`), account revival/closing lamport drain, and duplicate mutable account aliasing. Use when reviewing Solana smart contracts."
family: blockchain
tier: core
triggers: ["solana smart contract audit", "anchor security", "arbitrary cpi solana", "pda bump seed", "account closing solana"]
cwe: [CWE-284, CWE-345]
owasp: []
attack: []
capec: []
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
corpus_sparse: true
---


# Solana Anchor and SVM Program Audit - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **core** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Auditing an Anchor program means checking the account model rather than the arithmetic: every account in the instruction context is validated by its declared type, but anything read through `remaining_accounts`, passed to a CPI, or reached via the instructions sysvar is validated by hand or not at all. The audit walks those boundaries and verifies owner, discriminator, PDA seeds, signer and writable flags, and the expected account count.

- **`remaining_accounts` bypasses the derive.** Nothing in that slice is type-checked, ownership-checked, or seed-validated, so each element is a wire-format parse the program must do itself.
- **A generic `Program<'info>` only proves executability.** Pinning the callee with `Program<'info, T>` or an explicit ID check is what prevents an attacker-supplied program from receiving forwarded authority.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the instruction reads `ctx.remaining_accounts` **THEN** assert the expected count and validate owner, discriminator, seeds, and signer status for each element before use.
2. **IF** the program performs a CPI **THEN** confirm the target program ID is pinned and no `remaining_accounts` slice is forwarded unchecked.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the instruction context, the account list per instruction, and every CPI site — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Anchor 1.x with `#[derive(Accounts)]` constraints, explicit checks on `remaining_accounts`, and `anchor test` against a local validator
- **First Check:** `anchor build && anchor test`

1. Confirm the target surface: list every instruction, its declared `Accounts` struct, and every place an `AccountInfo` is read outside that struct.
2. Choose the branch: derive review for declared accounts, remaining-accounts review for dynamic slices, and CPI review for forwarded authority and callee identity.
3. Define the differential: for each unchecked account, substitute an attacker-controlled account of the right shape and observe whether the instruction still succeeds; a success is the finding.
4. Name the stop condition: every account either has a derive constraint or an explicit runtime check with the expected count asserted.
5. Prove it: a test that passes a wrong owner, wrong discriminator, or duplicate mutable account and asserts the instruction fails.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``Signer<'info>` and `mut` in the Accounts struct` | Declarative checks Anchor enforces before the handler runs; anything outside the struct has no equivalent. |
| ``Program<'info, Token>` versus bare `Program<'info>`` | Pins the callee's program ID, preventing an attacker-supplied program from receiving forwarded signer authority. |
| ``find_program_address` with canonical bump` | Deriving and comparing the PDA is the only way to know an account is the one the program intended. |
| ``chunks_exact` plus a remainder check on remaining accounts` | The count assertion; a loop that ignores the remainder silently accepts trailing accounts. |

## Worked Contrast

**Attacker-Controlled Accounts and an Unpinned CPI:**

```rust
pub fn settle(ctx: Context<Settle>, amount: u64) -> Result<()> {
    // BUG: remaining_accounts are used with no count, owner or seed validation
    let vault = &ctx.remaining_accounts[0];
    let dest = &ctx.remaining_accounts[1];
    let ix = token::Transfer { amount };
    // BUG: generic Program, so any executable account can be the callee
    token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), ix), amount)?;
    Ok(())
}
```

**Count Asserted, Accounts Validated, Callee Pinned:**

```rust
pub fn settle(ctx: Context<Settle>, amount: u64) -> Result<()> {
    require_eq!(ctx.remaining_accounts.len(), 2, ErrorCode::BadAccountCount);
    let vault = &ctx.remaining_accounts[0];
    let dest = &ctx.remaining_accounts[1];

    require_keys_eq!(*vault.owner, crate::ID, ErrorCode::BadOwner);
    require!(!dest.executable, ErrorCode::ExecutableAccount);
    require!(dest.is_writable, ErrorCode::NotWritable);

    let (expected, bump) = Pubkey::find_program_address(&[b"vault", ctx.accounts.authority.key().as_ref()], &crate::ID);
    require_keys_eq!(vault.key(), expected, ErrorCode::BadVault);

    let ix = token::Transfer { amount };
    token::transfer(
        CpiContext::new(ctx.accounts.token_program.to_account_info(), ix).with_signer(&[&[b"vault", ctx.accounts.authority.key().as_ref(), &[bump]]]),
        amount,
    )?;
    Ok(())
}
```

**Why this matters:** Reading `remaining_accounts` by index trusts whatever the caller supplied, and a generic `Program` accepts any executable account as the token program, so an attacker routes the transfer through their own program which receives the signer authority. Asserting the count, checking owner and seeds, and typing the callee to `Program<'info, Token>` restricts the instruction to the accounts and program the protocol intended.

## When It Is NOT This Issue

- **Account validated by a preceding instruction in the same transaction.** Acceptable only when the program itself checks the result; a different instruction's check is not enforcement.
- **`init` constraint on a PDA.** Anchor validates the seeds during creation; the finding is about reads, not creation.
- **Duplicate account that cannot be written twice.** Anchor's duplicate-mutable check may already cover it; verify the version before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `solana-anchor-and-svm-program-audit` based solely on surface keywords (`Signer<'info>`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `solana-anchor-and-svm-program-audit` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: solana-anchor-and-svm-program-audit
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284, CWE-345`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md) - Blue Detection/Defense Counterpart
- [`smart-contract-audit`](../smart-contract-audit/SKILL.md) - Blockchain (core)
- [`defi-attack-patterns`](../defi-attack-patterns/SKILL.md) - Blockchain (flagship)
- [`evm-exploitation-and-tooling`](../evm-exploitation-and-tooling/SKILL.md) - Blockchain (core)
- [`wallet-and-key-management-attacks`](../wallet-and-key-management-attacks/SKILL.md) - Blockchain (core)
- [`reentrancy-and-call-ordering`](../reentrancy-and-call-ordering/SKILL.md) - Blockchain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `solana-anchor-and-svm-program-audit` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
