---
name: cryptocurrency-and-onchain-tracing-osint
description: "Traces public on-chain cryptocurrency flows (EVM, Bitcoin UTXO, Solana): common-input-ownership heuristics, change-address identification, bridge/DEX hop tracking, OFAC/ransomware cluster attribution, and exchange deposit tag correlation. Use in ransomware financial tracing or Web3 fraud investigations."
family: osint-and-red-operations
tier: leaf
triggers: ["crypto tracing osint", "blockchain forensics", "utxo clustering", "onchain investigation"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Cryptocurrency and Onchain Tracing OSINT - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Following value across public ledgers: cluster addresses using co-spend heuristics on UTXO chains, read contract event logs on account-based chains, and follow bridge hops where value changes representation. The output is a flow graph with confidence levels, because clustering is a heuristic and a bridge hop breaks address continuity by design.

- **Clustering is probabilistic.** Co-spend implies common control with high but not certain confidence; a custodial service's addresses co-spend for thousands of users.
- **A bridge breaks the trail into two trails.** The destination-side address is linked by the bridge event, not by address continuity, so the evidence is the event log.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the chain is UTXO-based **THEN** cluster on co-spend and mark exchange deposit clusters as service-controlled rather than user-controlled.
2. **IF** the value crosses a bridge **THEN** record the source transaction, the bridge contract event, and the destination transaction as three observations.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a starting address or transaction, a chain, and the block explorer or node interface used for each read — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A chain RPC or explorer API for transaction and event reads, with every observation stored with block height and timestamp
- **First Check:** `cast receipt 0xabc... --rpc-url $RPC`

1. Confirm the target surface: record the starting address, chain, and the block height at which the observation begins.
2. Choose the branch: UTXO clustering for co-spend analysis, event-log tracing for token movements, and bridge tracing when value changes representation.
3. Define the differential: for each hop, the evidence is a transaction that spends from the previous output or an event that credits the next address; a hop without that evidence is an inference.
4. Name the stop condition: a hop budget and a confidence floor, so the trail stops at a service deposit rather than speculating past it.
5. Prove it: each edge in the flow records the transaction hash, block height, and the mechanism (spend, event, bridge), so a reviewer can replay the read.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Co-spend input set on a UTXO transaction` | Evidence that one entity controlled the inputs at signing time; weak where a service batches withdrawals. |
| `Contract event log with topic and data` | Authoritative record of a token movement, independent of any explorer's labelling. |
| `Bridge deposit and withdrawal pair` | Links two chains through a contract event rather than through address continuity. |
| `Exchange deposit cluster` | A terminal point for user-level tracing; the service controls the address, not the user. |

## Worked Contrast

**Address Continuity Assumed Across a Bridge:**

```text
Address A sends to a bridge contract on chain 1.
Search chain 2 for the same address string and continue tracing from it.
# BUG: bridge output addresses are unrelated; the search result is a different account that happens to share a string
```

**Bridge Hop Evidenced by the Contract Event:**

```text
Chain 1: tx 0xaaa spends from A into bridge contract B at block 19000000.
Event: DepositInitiated(recipient=0xR, amount, nonce) emitted in tx 0xaaa.
Chain 2: tx 0xbbb on the destination bridge emits WithdrawalFinalized(nonce, recipient=0xR) at block 8100000.
Link: matching nonce and amount across the two events, recorded with both transaction hashes.
```

**Why this matters:** A bridge exists precisely to break address continuity, so searching the destination chain for the same address string finds an unrelated account. The nonce and amount in the two contract events are the evidence that ties the source and destination transfers together, and storing both transaction hashes makes the link reproducible.

## When It Is NOT This Issue

- **Exchange cluster read as the user's address.** A deposit address is controlled by the service; tracing to it ends the user-level trail.
- **Same address string on two chains.** Address formats are shared across EVM chains, so a string match is not a link.
- **Explorer label treated as ground truth.** Labels are curated and sometimes wrong; confirm with the transaction itself.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cryptocurrency-and-onchain-tracing-osint` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cryptocurrency-and-onchain-tracing-osint` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cryptocurrency-and-onchain-tracing-osint
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cryptocurrency-and-onchain-tracing-osint` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 1 |
| Top sources | osint-tool-database (16) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 0 cases |
| Grounding | multi-dataset corpus-grounded |
