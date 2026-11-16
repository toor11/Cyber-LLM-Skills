---
name: network-protocol-grammar-fuzzer-development
description: "Builds stateful protocol QA test harnesses using Boofuzz or structured Scapy/Python state machines against local lab targets: session handshake callbacks, length/checksum sizers, target health monitors, and deterministic crash logging. Use when testing custom network daemons in an isolated lab."
family: security-assessment-tooling-and-automation
tier: leaf
triggers: ["boofuzz script", "protocol grammar fuzzer", "stateful fuzzing python", "s_initialize"]
cwe: [CWE-20]
owasp: []
attack: []
capec: []
related: [nuclei-template-engineering, nmap-nse-audit-script-authoring, burp-montoya-and-jython-extension-development, mitmproxy-addon-scripting]
corpus_sparse: true
---


# Network Protocol Grammar Fuzzer Development - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Security Assessment Tooling and Automation`](../README.md) | Tier: **leaf** | Paired Counterpart: [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Stateful protocol fuzzing against a lab daemon: a session object drives the handshake and keeps per-connection state, a block graph describes message fields with dependencies, and sizers compute length and checksum fields from the mutated payload so the target parses the message instead of rejecting it. The engineering decision is where the grammar ends and raw mutation begins — a fully specified message reaches deep code paths but cannot generate the malformed variants that matter.

- **Sizers are what make a message reachable.** A length field computed from the mutated block, and a checksum recomputed after mutation, decide whether the target's parser processes the input at all.
- **The target must be re-usable between cases.** A health check after each run restarts a crashed service so one crash does not end the campaign, and each crash is logged with the exact message bytes.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the protocol has a handshake **THEN** put it in the session's connect callback and mutate only post-handshake messages, so every case starts from a valid session.
2. **IF** the daemon crashes on the first malformed length **THEN** keep the sizer for the outer frame and mutate only the payload, so the parser keeps reaching the inner code.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an isolated lab target, a captured valid message exchange, and a restartable service — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Python 3.11+ with a stateful fuzzer library (`boofuzz` Session/Request/Block, `s_size`, `checksum`) or `scapy` for hand-built frames, plus JSONL crash logging
- **Mandatory Self-Validation Command:** `python -m py_compile proto_fuzz.py && python proto_fuzz.py --help`

1. Confirm the target surface: capture one valid exchange from the lab daemon, identify the frame boundaries, and note which fields are length- or checksum-derived.
2. Choose the branch: block-graph fuzzing when the protocol has nested fields, raw frame mutation when the framing is opaque, and a recorded-session replay when the handshake is stateful and hard to model.
3. Define the differential: replay the captured valid message and confirm the daemon responds normally, then run one mutated case and confirm the difference is the mutation and not the harness.
4. Name the stop condition: a case count or time budget per run, a restart count ceiling, and a crash log that captures the message bytes for every failure.
5. Prove it: replay the logged crash message against a fresh instance and confirm the same failure, then minimise the frame while keeping the crash.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Session(target=..., sleep_time=...)` | Owns the connection lifecycle and pacing; the sleep is the load control that keeps the lab daemon responsive. |
| `Request with Blocks and a s_size field` | Declares the message shape and computes the length field, which is what gets mutation past the framing check. |
| `checksum block over the payload` | Recomputes the checksum after mutation so the target's integrity check does not reject every case. |
| `post_test_case callback with a health check` | Restarts a crashed daemon between cases and records which message killed it. |

## Worked Contrast

**Fuzzer That Mutates the Length Field and Never Restarts:**

```python
import random
import socket

frame = bytearray(b"\x10\x00GET /\x00")
for _ in range(10000):
    mutated = bytearray(frame)
    mutated[1] = random.randrange(256)  # BUG: corrupts the length, so the parser rejects the frame
    socket.create_connection(("127.0.0.1", 9000)).send(mutated)  # BUG: no restart, no logging
```

**Sizer-Preserving Mutation With Restart and Logging:**

```python
import json
import socket
import struct
import time

TARGET = ("127.0.0.1", 9000)

def send_frame(payload: bytes) -> None:
    frame = struct.pack(">H", len(payload)) + payload
    with socket.create_connection(TARGET, timeout=5) as sock:
        sock.sendall(frame)
        try:
            sock.recv(4096)
        except socket.timeout:
            pass

for i, payload in enumerate([b"GET /\x00", b"GET /" + b"A" * 64 + b"\x00"]):
    try:
        send_frame(payload)
    except OSError as exc:
        print(json.dumps({"case": i, "payload_hex": payload.hex(), "error": str(exc)}))
        time.sleep(1)
```

**Why this matters:** Randomising the length byte means the daemon's framing check discards almost every case before the parser runs, so the campaign explores the framing code and nothing else. Computing the length from the payload keeps every case well-formed at the outer layer, and the JSONL record with the payload hex is what makes a crash reproducible after the service restarts.

## When It Is NOT This Issue

- **Rejected frame read as parser robustness.** A daemon that closes the connection on a bad length has passed the framing check, not survived a parser test.
- **Crash on the first case from an invalid handshake.** A harness that skips the handshake exercises error paths only; the crash says nothing about post-auth code.
- **Resource exhaustion counted as a memory bug.** Opening thousands of connections per second exhausts file descriptors, which is the harness's load, not a vulnerability.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER execute network or target checks without verifying the target against an explicit `--scope-file` allowlist.
- NEVER run unbounded concurrency, infinite retries, or state-mutating/destructive requests.
- NEVER hallucinate deprecated wrapper methods around `Session(` — pin exact imports and handle exceptions explicitly.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `network-protocol-grammar-fuzzer-development` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: network-protocol-grammar-fuzzer-development
- **Target Stack & Schema**: Python 3.11+ typed CLI (`argparse`, bounded timeouts, scope allowlist, key API: `Session(`)
- **Safety, Scope & Exit-Code Guards**: [Scope allowlist, streaming bounds, dry-run/read-only default, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [How benign inputs, sidecars, and malformed records are handled]
- **Implementation**:
  [Runnable, self-contained code/YAML/Rego block following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile network_protocol_grammar_fuzzer.py; python network_protocol_grammar_fuzzer.py --help`
```

## Related Sub-Skills

- [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) - Blue Detection/Defense Counterpart
- [`nuclei-template-engineering`](../nuclei-template-engineering/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`nmap-nse-audit-script-authoring`](../nmap-nse-audit-script-authoring/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`burp-montoya-and-jython-extension-development`](../burp-montoya-and-jython-extension-development/SKILL.md) - Security Assessment Tooling and Automation (flagship)
- [`mitmproxy-addon-scripting`](../mitmproxy-addon-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)
- [`openapi-and-graphql-schema-auditor-scripting`](../openapi-and-graphql-schema-auditor-scripting/SKILL.md) - Security Assessment Tooling and Automation (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `network-protocol-grammar-fuzzer-development` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
