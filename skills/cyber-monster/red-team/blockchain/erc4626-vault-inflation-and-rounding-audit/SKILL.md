---
name: erc4626-vault-inflation-and-rounding-audit
description: "Audits ERC-4626 tokenized vaults, lending shares, and staking reward distributors: first-depositor donation/share-inflation attacks (virtual shares/assets offset defense), rounding direction invariants (`previewDeposit` vs `previewMint` favoring the vault), and fee-on-transfer/rebasing token accounting mismatches. Use when auditing DeFi vault math."
family: blockchain
tier: leaf
triggers: ["erc4626 inflation attack", "vault rounding direction", "virtual shares offset", "fee on transfer accounting"]
cwe: [CWE-682]
owasp: []
attack: []
capec: []
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
corpus_sparse: true
---


# Erc4626 Vault Inflation and Rounding Audit - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Auditing an ERC-4626 tokenized vault's share math: `previewDeposit`/`previewMint`/`previewWithdraw`/`previewRedeem` must round in the vault's favour, `totalAssets()` must not be inflatable by a direct transfer, and the first-depositor path must not let an attacker set an arbitrary share price. The audit question for every conversion is which party the truncation favours and whether repeated small operations can accumulate a gain.

- **EIP-4626 fixes the rounding directions.** `previewDeposit` and `previewRedeem` floor, `previewMint` and `previewWithdraw` ceil; a vault that inverts one of these leaks value on every call in that direction.
- **`totalAssets()` from `balanceOf` is a donation surface.** A direct transfer changes the share price without a deposit event, which is the mechanism behind both inflation and griefing.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** `totalAssets()` returns `asset.balanceOf(address(this))` **THEN** the donation path is open and the virtual-share offset or internal accounting becomes the primary control to check.
2. **IF** `_decimalsOffset()` is zero **THEN** the first-depositor share price is unbounded; check for a minimum initial deposit or dead shares before treating the vault as safe.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the conversion functions, the `totalAssets()` source, and the `_decimalsOffset()` value — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** OpenZeppelin ERC4626 with explicit `Math.Rounding` per EIP-4626, Foundry fuzz tests over deposit and redeem amounts, and a donation test
- **First Check:** `forge test --match-test testVaultRounding -vvv`

1. Confirm the target surface: read the four preview functions, `totalAssets()`, `_decimalsOffset()`, and any override of `_convertToShares` or `_convertToAssets`.
2. Choose the branch: rounding review when the conversions are overridden, donation review when `totalAssets` reads a balance, and first-deposit review when the offset is zero.
3. Define the differential: deposit then immediately redeem the same amount and compare the returned assets to the deposit; a loss greater than rounding is the finding, and a gain for the depositor is worse.
4. Name the stop condition: all four conversions round in the vault's favour, and a direct transfer does not change the share price a subsequent depositor receives.
5. Prove it: a fuzz test over amounts asserting `previewRedeem(previewDeposit(x)) <= x`, plus a donation test asserting the share price is unchanged.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``previewWithdraw` with `Math.Rounding.Ceil`` | Burns at least the shares owed; a `Floor` here under-burns and leaks value on every withdrawal. |
| ``totalAssets()` returning a tracked balance` | Immune to direct transfers, which removes the donation lever entirely. |
| ``_decimalsOffset()` above zero` | Makes the virtual share supply large relative to the first deposit, raising the cost of an inflation attack. |
| ``previewRedeem(previewDeposit(x)) <= x`` | The round-trip property a fuzz test asserts; a violation means the vault pays out more than it took in. |

## Worked Contrast

**Vulnerable ERC-4626 Vault (`balanceOf` Donation + Zero Offset + Floor Withdraw):**

```solidity
contract VulnerableVault is ERC4626 {
    // BUG 1: Direct ERC20 transfers inflate totalAssets() and manipulate share price
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this));
    }
    // BUG 2: _decimalsOffset() == 0 leaves first/small depositors exposed to share-inflation griefing/theft
    // BUG 3: EIP-4626 REQUIRES previewWithdraw to round UP (Ceil); Floor under-burns shares!
    function previewWithdraw(uint256 assets) public view override returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Floor);
    }
}
```

**Hardened ERC-4626 Vault (Internal Accounting + Virtual Offset + Vault-Favoring Rounding):**

```solidity
contract HardenedVault is ERC4626 {
    uint256 private _trackedAssets; // Mutated only in _deposit, _withdraw, and gated report()

    function _decimalsOffset() internal view override returns (uint8) {
        return 6; // Virtual shares/assets (10^offset) make donation inflation economically infeasible
    }
    function totalAssets() public view override returns (uint256) {
        return _trackedAssets; // Immune to unsolicited IERC20.transfer() donations
    }
    // EIP-4626 Canonical Rounding Invariant (ALWAYS favor the vault):
    // previewDeposit: Floor | previewMint: Ceil | previewWithdraw: Ceil | previewRedeem: Floor
    function previewWithdraw(uint256 assets) public view override returns (uint256) {
        return _convertToShares(assets, Math.Rounding.Ceil);
    }
}
```

**Why this matters:** ERC-4626 security rests on three invariants: (1) track internal `_trackedAssets` (measured via deposit balance deltas) rather than raw `balanceOf`, (2) set non-zero virtual `_decimalsOffset()` + minimum seed deposit/dead-shares, and (3) enforce `Floor/Ceil/Ceil/Floor` on `previewDeposit/previewMint/previewWithdraw/previewRedeem`.

## When It Is NOT This Issue

- **One-wei round-trip loss.** Integer division loses precision; a loss bounded by one wei per operation is expected and not exploitable.
- **Donation that only grieves.** A donation that raises the share price without letting the donor profit is a griefing vector to document, not a theft.
- **`_decimalsOffset()` of zero with a minimum initial deposit.** The offset is one mitigation; a seeded minimum deposit achieves a similar bound, so check both before reporting.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `erc4626-vault-inflation-and-rounding-audit` based solely on surface keywords (`_decimalsOffset()`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `erc4626-vault-inflation-and-rounding-audit` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: erc4626-vault-inflation-and-rounding-audit
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-682`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `erc4626-vault-inflation-and-rounding-audit` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
