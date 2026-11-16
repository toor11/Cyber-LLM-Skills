---
name: move-aptos-and-sui-smart-contract-audit
description: "Audits Move smart contracts on Sui and Aptos: capability/witness object leakage (`drop`/`store`/`key`/`copy` ability mistakes), shared-object contention/ordering assumptions, unchecked `Coin` split/merge accounting, and package upgrade policy risks. Use when reviewing Move modules."
family: blockchain
tier: leaf
triggers: ["move smart contract audit", "sui security", "aptos move audit", "ability drop store key", "hot potato move"]
cwe: [CWE-284, CWE-682]
owasp: []
attack: []
capec: []
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
corpus_sparse: true
---


# Move Aptos and Sui Smart Contract Audit - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Auditing Move code on Aptos and Sui means auditing resource semantics: abilities (`key`, `store`, `copy`, `drop`) decide what can be stored, copied, or discarded, and capability objects decide what an entry function may do. The characteristic defects are a resource that can be copied or dropped when it should not be, a capability stored where a module cannot revoke it, and an entry function that accepts an authority object from the caller.

- **Abilities are the access-control declaration.** A struct with `copy` can duplicate a token, and one with `drop` can discard a capability; the ability list is the security property, not a detail.
- **Capabilities must be unforgeable and revocable.** A `Capability` struct created only by the module and stored at a known address is the pattern; one constructible from public fields is a privilege grant to anyone.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a token or receipt struct has `copy` or `drop` **THEN** confirm the design intends duplication or discard, because both defeat supply accounting.
2. **IF** an entry function takes a capability as a parameter **THEN** check where that capability can come from, since a caller-supplied authority is a confused-deputy path.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the module's resource definitions, their abilities, and every entry function's parameters — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Move on Aptos (`module`, `struct`, `entry fun`, `friend`) or Sui (`module`, `public struct`, `entry fun`, `TxContext`), tested with the chain's CLI
- **First Check:** `aptos move test`

1. Confirm the target surface: list every struct with its abilities, and every entry and public function with its parameters and signer requirements.
2. Choose the branch: ability review for resource supply semantics, capability review for authority objects, and entry-function review for caller-supplied authority and signer checks.
3. Define the differential: for each resource, attempt to copy, drop, or construct it from outside the module and observe the compiler or runtime rejection; an acceptance is the finding.
4. Name the stop condition: every privilege-granting resource is creatable only inside its module and stored at an address the module controls.
5. Prove it: a test that attempts the unauthorised construction or duplication and asserts the abort, plus the ability list quoted in the report.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``has key, store` without `copy` or `drop`` | The safe default for a token: it can be stored and transferred but not duplicated or silently discarded. |
| `Capability struct with private fields` | Prevents construction outside the module, which is what makes it an authority rather than a suggestion. |
| ``friend` or `public(friend)` visibility` | Restricts who may call a privileged function; its absence is the finding. |
| ``&signer` parameter requirement` | Proves the caller controls the address; a function that takes an authority object instead does not. |

## Worked Contrast

**Copyable Token and Caller-Supplied Capability:**

```rust
module 0x1::token {
    struct Token has key, store, copy { amount: u64 } // BUG: copy defeats supply accounting

    struct MintCap has key, store { } // BUG: public fields allow forging a capability

    public entry fun mint(cap: MintCap, to: address, amount: u64) { // BUG: capability from the caller
        move_to<Token>(account::new_signer_from_address(to), Token { amount });
    }
}
```

**Non-Copyable Token With a Module-Owned Capability:**

```rust
module 0x1::token {
    struct Token has key, store { amount: u64 } // no copy, no drop

    struct MintCap has key { } // fields private; only this module can create it

    public entry fun mint(_admin: &signer, to: address, amount: u64) acquires MintCap {
        let cap = borrow_global<MintCap>(@0x1);
        assert!(exists<MintCap>(@0x1), error::not_found(0));
        move_to<Token>(account::new_signer_from_address(to), Token { amount });
        let _ = cap;
    }
}
```

**Why this matters:** A `copy` ability lets any holder duplicate the token, so the supply the module believes it tracks is fiction, and a capability struct with public fields can be constructed by anyone, so `mint` accepts authority the caller fabricated. Removing `copy` and `drop` from the token and keeping the capability's fields private with the module as its only creator makes both the supply and the authority a property the module enforces.

## When It Is NOT This Issue

- **`drop` on a receipt or event struct.** Discarding a receipt is usually intended; the finding is `drop` on something that carries value or authority.
- **Capability stored under a user address by design.** If the module can revoke or the user opts in, the trust model differs from a module-owned capability.
- **`friend` declaration that is broad.** Broad friendship is a design choice to document; the finding is a missing restriction on a value-moving function.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `move-aptos-and-sui-smart-contract-audit` based solely on surface keywords (`has key, store`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `move-aptos-and-sui-smart-contract-audit` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: move-aptos-and-sui-smart-contract-audit
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284, CWE-682`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `move-aptos-and-sui-smart-contract-audit` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284, CWE-682`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
