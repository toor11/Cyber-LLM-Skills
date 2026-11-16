# Blockchain

> Tree: `red-team/blockchain` | **22 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`defi-attack-patterns`](defi-attack-patterns/SKILL.md) | **flagship** | Exploits DeFi protocol logic: flash loan manipulation, oracle manipulation, price and share accounting errors, MEV extraction and liquidation abu |
| [`access-control-and-initialization`](access-control-and-initialization/SKILL.md) | **core** | Finds smart contract access control and initialization flaws: unprotected initializers, missing modifiers, proxy admin mistakes and privilege esc |
| [`eip712-signature-replay-and-account-abstraction`](eip712-signature-replay-and-account-abstraction/SKILL.md) | **core** | Audits EIP-712 typed signatures, EIP-2612 `permit`, meta-transactions, and ERC-4337 Account Abstraction (`EntryPoint`, `validateUserOp`, Paymaste |
| [`evm-exploitation-and-tooling`](evm-exploitation-and-tooling/SKILL.md) | **core** | Works at the EVM level: bytecode analysis, storage layout, calldata crafting and tooling with Foundry, Hardhat and cast |
| [`flash-loan-and-capital-attacks`](flash-loan-and-capital-attacks/SKILL.md) | **core** | Uses flash loans and atomic capital to exploit assumptions about available liquidity, governance snapshots and collateral timing |
| [`oracle-and-price-manipulation`](oracle-and-price-manipulation/SKILL.md) | **core** | Manipulates price oracles and derived accounting: spot price abuse, TWAP manipulation, stale oracle conditions and decimal scaling errors |
| [`reentrancy-and-call-ordering`](reentrancy-and-call-ordering/SKILL.md) | **core** | Exploits reentrancy and unsafe external call ordering: single-function and cross-function reentrancy, read-only reentrancy and callback manipulat |
| [`smart-contract-audit`](smart-contract-audit/SKILL.md) | **core** | Audits smart contracts for security defects: access control, arithmetic, external call ordering and upgrade patterns, using static review plus te |
| [`solana-anchor-and-svm-program-audit`](solana-anchor-and-svm-program-audit/SKILL.md) | **core** | Audits Solana Rust/Anchor programs on the SVM: missing signer/owner checks (`Signer<'info>`, `Account<'info, T>`), arbitrary Cross-Program Invoca |
| [`wallet-and-key-management-attacks`](wallet-and-key-management-attacks/SKILL.md) | **core** | Attacks wallet and key handling: weak key generation, signing request confusion, approval abuse and key storage exposure |
| [`arithmetic-and-precision-bugs`](arithmetic-and-precision-bugs/SKILL.md) | **leaf** | Exploits arithmetic and precision defects: overflow in unchecked blocks, rounding direction, share and fee accounting drift, and decimal mismatch |
| [`bridge-and-cross-chain`](bridge-and-cross-chain/SKILL.md) | **leaf** | Assesses bridge and cross-chain designs: message verification gaps, replay and signature threshold flaws, and wrapped asset accounting |
| [`defi-attack-patterns-amm-and-liquidity`](defi-attack-patterns-amm-and-liquidity/SKILL.md) | **leaf** | AMM and liquidity pool attacks |
| [`defi-attack-patterns-lending-and-collateral`](defi-attack-patterns-lending-and-collateral/SKILL.md) | **leaf** | Lending and collateral attacks |
| [`erc4626-vault-inflation-and-rounding-audit`](erc4626-vault-inflation-and-rounding-audit/SKILL.md) | **leaf** | Audits ERC-4626 tokenized vaults, lending shares, and staking reward distributors: first-depositor donation/share-inflation attacks (virtual shar |
| [`governance-and-token-attacks`](governance-and-token-attacks/SKILL.md) | **leaf** | Attacks governance and token mechanics: vote buying and flash-loan voting, proposal execution gaps, token accounting abuse and delegation flaws |
| [`move-aptos-and-sui-smart-contract-audit`](move-aptos-and-sui-smart-contract-audit/SKILL.md) | **leaf** | Audits Move smart contracts on Sui and Aptos: capability/witness object leakage (`drop`/`store`/`key`/`copy` ability mistakes), shared-object con |
| [`smart-contract-audit-static-analysis-tooling`](smart-contract-audit-static-analysis-tooling/SKILL.md) | **leaf** | Smart contract static analysis tooling |
| [`smart-contract-audit-testing-and-invariants`](smart-contract-audit-testing-and-invariants/SKILL.md) | **leaf** | Contract testing and invariant fuzzing |
| [`wallet-and-key-management-attacks-approval-and-permit-abuse`](wallet-and-key-management-attacks-approval-and-permit-abuse/SKILL.md) | **leaf** | Token approval and permit abuse |
| [`wallet-and-key-management-attacks-key-generation-weakness`](wallet-and-key-management-attacks-key-generation-weakness/SKILL.md) | **leaf** | Wallet key generation weakness |
| [`web3-infrastructure-and-rpc`](web3-infrastructure-and-rpc/SKILL.md) | **leaf** | Assesses web3 infrastructure: exposed RPC endpoints, node and validator configuration, front-end and DNS takeover of dApps, and key material in d |
