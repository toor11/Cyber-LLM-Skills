---
name: foundry-and-echidna-invariant-harness-scripting
description: "Authors Solidity stateful invariant test suites in Foundry (`StdInvariant`, bounded `Actor`/handler contracts, ghost accounting variables) and Echidna property harnesses: verifying solvency, share-to-asset conservation, and access-control invariants across random call sequences. Use when writing DeFi/smart-contract fuzz harnesses."
family: security-assessment-tooling-and-automation
tier: core
triggers: ["foundry invariant test", "stdinvariant handler", "echidna harness", "ghost variables solidity"]
cwe: [CWE-682]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Foundry and Echidna Invariant Harness Scripting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **core** | Paired Counterpart: [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Stateful property testing of a contract system: a handler contract drives the protocol through a bounded action set while an `invariant_` function asserts a property that must hold after every call sequence. Echidna and Foundry differ in search strategy, not in the property, so the harness is written once as a property plus a handler and run under both engines to catch different sequences.

- **The invariant is the specification.** A property that is trivially true (a constant comparison, a balance check against itself) gives a green run that proves nothing.
- **Handler bounds are part of the property.** Actor count, value bounds, and blocked selectors define the reachable state space; an unbounded handler finds arithmetic dead ends rather than protocol bugs.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the system has roles **THEN** give the handler a bounded actor set and assert per-actor accounting, not just global totals.
2. **IF** a counterexample appears **THEN** shrink it before reporting; Foundry persists the sequence and Echidna prints the call list, and the minimal sequence is the finding.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a deployed target, a handler with bounded actions, and a property that can fail — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Foundry 1.x (`StdInvariant`, `targetContract`, `bound()`, `forge test --match-contract Invariant`) and Echidna (`echidna_` prefix, `echidna` config)
- **Mandatory Self-Validation Command:** `forge test --match-contract Invariant -vv`

1. Confirm the target surface: list the external functions the property depends on and the roles allowed to call them, then map each to a handler action.
2. Choose the branch: accounting invariant (sum of balances equals total supply), access invariant (no non-owner path changes an owner-only field), or liveness invariant (a withdrawal always succeeds for a solvent position).
3. Define the differential: run the handler against the unmodified deployment and record which actions the fuzzer actually reached; the probe run is the same harness with the candidate fix, and the differential is the failing sequence disappearing.
4. Name the stop condition: call depth, run count, and a corpus directory so a counterexample is reproducible byte-for-byte.
5. Prove it: export the minimal failing call sequence, replay it against the deployed bytecode, and state the invariant violated at the last call.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `function invariant_totalSupplyMatchesBalances() public view` | A property the fuzzer can actually falsify; view-only invariants are cheap to check after every call. |
| `targetContract(address(handler))` | Restricts the action set to the handler, which is how actor count and call bounds are enforced. |
| `bound(value, min, max)` | Keeps generated values inside the protocol's real domain instead of arithmetic extremes. |
| `function echidna_solvent() public view returns (bool)` | Echidna's naming contract; a `false` return is a counterexample, not an assertion failure. |

## Worked Contrast

**Invariant That Cannot Fail:**

```solidity
contract VaultInvariant is StdInvariant, Test {
    Vault vault;
    function setUp() public { vault = new Vault(); }
    function invariant_balanceIsNonNegative() public view {
        // BUG: uint cannot be negative, so this can never fail
        assertGe(vault.totalAssets(), 0);
    }
}
```

**Handler-Bounded Accounting Invariant:**

```solidity
contract Handler is Test {
    Vault vault;
    address[] public actors;
    constructor(Vault v) { vault = v; actors.push(address(0xA11CE)); }
    function deposit(uint256 amt) public {
        amt = bound(amt, 1, 1e24);
        vault.deposit(amt, actors[0]);
    }
    function withdraw(uint256 amt) public {
        amt = bound(amt, 0, vault.balanceOf(actors[0]));
        vault.withdraw(amt, actors[0], actors[0]);
    }
}

contract VaultInvariant is StdInvariant, Test {
    Vault vault;
    Handler handler;
    function setUp() public {
        vault = new Vault();
        handler = new Handler(vault);
        targetContract(address(handler));
    }
    function invariant_sharesBackedByAssets() public view {
        assertGe(vault.totalAssets(), vault.totalSupply());
    }
}
```

**Why this matters:** An invariant over an unsigned value is a tautology, so the green result carries no information. Bounding the handler's inputs to the protocol's real domain and asserting a cross-quantity relation gives the fuzzer a property it can falsify, and `targetContract` keeps the search inside the actions that exist.

## When It Is NOT This Issue

- **Invariant true by type.** Non-negativity on an unsigned integer, or equality between a value and itself, cannot fail; such a run is not evidence.
- **Fuzzer never reached the branch.** A passing run with zero calls into the handler proves nothing about the code; check reached-action coverage.
- **Unrealistic input domain.** Values above total supply saturate balances and produce reverts that look like invariant violations.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `StdInvariant` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `foundry-and-echidna-invariant-harness-scripting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: foundry-and-echidna-invariant-harness-scripting
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `StdInvariant`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile foundry_and_echidna_invariant.py; python foundry_and_echidna_invariant.py --help`
```

## Related Sub-Skills

- [`detection-engineering`](../../../blue-team/detection-and-monitoring/detection-engineering/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `foundry-and-echidna-invariant-harness-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
