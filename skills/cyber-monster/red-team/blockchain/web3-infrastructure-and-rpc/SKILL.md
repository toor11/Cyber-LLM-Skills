---
name: web3-infrastructure-and-rpc
description: "Assesses web3 infrastructure: exposed RPC endpoints, node and validator configuration, front-end and DNS takeover of dApps, and key material in deployments. Use when the target is dApp infrastructure rather than contract logic."
family: blockchain
tier: leaf
triggers: ["web3 rpc exposure", "dapp frontend attack", "node misconfiguration", "ens takeover"]
cwe: [CWE-284]
owasp: []
attack: []
capec: [CAPEC-116]
related: [smart-contract-audit, defi-attack-patterns, evm-exploitation-and-tooling, wallet-and-key-management-attacks]
---


# Web3 Infrastructure and Rpc - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Blockchain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md)

## Mechanism and Preconditions

The infrastructure around contracts: who can reach an RPC endpoint and which methods it exposes, how dApp front-ends resolve their dependencies, and where deployment keys live. The characteristic failures are an open node exposing `eth_sendTransaction` on an unlocked account, a front-end loading a script from a mutable source, and a deployment key in a CI variable with no rotation.

- **Method exposure is the RPC's permission model.** A node that answers `eth_sendTransaction` for an unlocked account lets any client spend that account's balance.
- **The front-end is part of the trust boundary.** A dApp that loads its provider or a script from a mutable URL can be changed without touching the contract.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the endpoint is reachable from the internet **THEN** enumerate the enabled namespaces and specifically test the signing methods, because that is where the exposure is.
2. **IF** the dApp loads third-party scripts **THEN** record each origin and whether an integrity attribute is present.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`secure-code-review`](../../../blue-team/application-security/secure-code-review/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — the endpoint URL, the exposed namespaces, and the front-end's dependency origins — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** JSON-RPC method enumeration against an authorised endpoint, CSP and dependency review for the front-end, and a deployment-key inventory
- **First Check:** `cast rpc eth_accounts --rpc-url $RPC`

1. Confirm the target surface: the endpoint, its reachability, the enabled namespaces, and the front-end origins in use.
2. Choose the branch: RPC exposure review for signing and admin methods, front-end review for dependency integrity, and key review for deployment and upgrade authority.
3. Define the differential: call an information method (baseline) and a signing method (probe); a signing method that succeeds without authorisation is the finding.
4. Name the stop condition: each namespace tested with one read-only method and one sensitive method, with no state-changing call executed.
5. Prove it: the method name, the response, and the endpoint, with a note that no transaction was submitted, so the evidence shows exposure without impact.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ``eth_accounts` on an internet-reachable endpoint` | Reveals whether the node holds accounts and is the prerequisite for signing exposure. |
| ``eth_sendTransaction` availability` | The sensitive method; availability plus an unlocked account is the exposure, and it must be probed without sending a real transaction. |
| `Content-Security-Policy and dependency origin` | Decides whether a front-end can be altered by a third party. |
| `Deployment key location and rotation` | Where the upgrade authority lives, and whether it can be rotated without redeploying. |

## Worked Contrast

**Open Node With Unlocked Accounts:**

```bash
geth --http --http.addr 0.0.0.0 --http.api eth,personal,admin --unlock 0xABC --allow-insecure-unlock
# BUG: signing, personal and admin namespaces exposed on every interface with an unlocked account
```

**Namespaces Limited to Reads:**

```bash
geth --http --http.addr 127.0.0.1 --http.api eth,net,web3
# eth_accounts returns empty; signing requires an external signer
cast rpc eth_accounts --rpc-url http://127.0.0.1:8545
cast rpc admin_nodeInfo --rpc-url http://127.0.0.1:8545 || echo "admin disabled (expected)"
```

**Why this matters:** Exposing `personal` and `admin`, binding to all interfaces, and unlocking an account together let any reachable client sign with that account, which is a direct loss of funds. Binding to loopback with a read-only namespace set removes both the reachability and the signing capability, and the two probes show the exposure is gone.

## When It Is NOT This Issue

- **`eth_accounts` returning an empty array.** The namespace is present but holds no keys; that is not a signing exposure.
- **Public RPC provider with rate limits.** A hosted endpoint that only serves reads is a service, not a finding.
- **Front-end loading from a CDN with integrity attributes.** The integrity hash pins the content; absence of the attribute is the finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `web3-infrastructure-and-rpc` based solely on surface keywords (`RPC open`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web3-infrastructure-and-rpc` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: web3-infrastructure-and-rpc
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-284`): [Exact lines/component, broken invariant, reachability, and concrete impact]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web3-infrastructure-and-rpc` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-284`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 18 |
| Distinct dataset sources | 3 |
| Top sources | osint-tool-database (16), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 2 cases |
| Grounding | multi-dataset corpus-grounded |
