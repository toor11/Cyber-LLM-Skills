---
name: cyber-monster
description: Cyber Monster (created by W4L33Dx - https://solo.to/w4l33dx) is a full-spectrum red-team and blue-team cybersecurity skill library (785 sub-skills across 19 families, single-skill or chained) covering web/API, network/AD, binary/RE, crypto, cloud/K8s, AI/MCP, smart contracts, mobile/ICS, OSINT, Sigma/YARA/SIEM detection, threat hunting, IR, forensics, malware analysis, AppSec, and security tooling. Use for any security audit, incident, forensic artifact, detection rule, or security script.
sources: vendored from https://github.com/W4L33Dx/Cyber-Monster (author W4L33Dx). Upstream had no LICENSE file at vendoring time; content redistributed with attribution to W4L33Dx. See docs/credits.md.
---

# Cyber Monster

Created by [W4L33Dx](https://solo.to/w4l33dx). One registered skill routing to
**785 self-contained sub-skills** across **19 families** (`red-team/` and
`blue-team/`). Each sub-skill `SKILL.md` solves a single technique in one read —
with IF/THEN decision rules, worked contrasts, false-positive traps,
anti-hallucination bans, and a strict output contract — and chains cleanly with
sibling or counterpart sub-skills when a task spans multiple layers or stages.

## Selection & Chaining Protocol (Follow Strictly)

Do not run a script. Do not call Python. Route by reading the files in this folder.

1. **Cheat table first.** Use the **Direct Symptom / Task Cheat Table** below.
   If a stage of the task matches a row, note that `SKILL.md`.
2. **Routing table second.** For any stage not in the cheat table, open
   [`ROUTING_TABLE.md`](ROUTING_TABLE.md) and match the user's words to a
   trigger cell.
3. **Family README third.** If the task is a whole area rather than one
   technique, open the matching family `README.md` from the 19-family table
   and pick the skill(s) it names.
4. **One skill by default; chain when the task has real stages.** Focused tasks
   use the single best-matched `SKILL.md`. When the job spans layers, stages,
   or teams, build a short ordered chain and work through it step by step:
   - **Compound / multi-layer target:** open one skill per layer or protocol
     (e.g., SSRF -> cloud metadata / IAM, OCR multimodal input -> MCP tool
     agency, JWT/OIDC flaw -> IDOR/authorization, Thread -> Matter).
   - **Pivot on evidence:** if testing or triage under the current skill reveals
     a new primitive or variant listed in its `related` header or *Variants and
     Decision Table*, hop directly to that linked `SKILL.md` for the next step.
   - **Red -> Blue handoff:** "find it *and* detect/fix/respond" runs the
     offensive skill to confirm root cause, then chains into its paired
     blue-team counterpart (`application-security` for code fixes,
     `detection-and-monitoring` for Sigma/SIEM rules, or `incident-response` /
     `digital-forensics` for containment and scoping).
   - **Full workflow / kill chain:** staged work (recon -> initial access ->
     privilege boundary, or triage -> forensics -> containment -> detection rule)
     opens each stage's `SKILL.md` as you reach it, passing concrete findings
     (sinks, indicators, versions, log fields) forward as inputs to the next.

   Load each `SKILL.md` **when you reach its stage**, not all up front, so
   context stays lean and the unused hundreds of skills stay on disk. Keep the
   chain minimal — if a parent and child overlap, open only the specific child.
   **Do NOT** read `PAYLOADS.md`, `QUERIES.md`, `TOOLS.md`, `SCENARIOS.md`, or
   `CASES.md` unless a row in that skill's *Variants and Decision Table*
   explicitly applies.
5. **Execute the Self-Critique Gate & Output Contract:** For every skill in the
   chain, verify its *Preconditions Checklist* and obey its *Anti-Hallucination
   Ban List*. For a single-skill task, format your answer with its *Strict
   Output Contract*; for a multi-skill chain, present each stage cleanly in
   execution order so every finding feeds the next stage's action.

## Direct 1-Hop Cheat Table (Common Tasks -> Exact `SKILL.md`)

| User Intent / Paste Signal | Open Directly (1 Hop) |
|---|---|
| SQL query / `ORDER BY` / ORM / `SQLSTATE` / `ORA-` | `red-team/web-and-application/sql-injection/SKILL.md` |
| Reflected / Stored / DOM XSS / CSP | `red-team/web-and-application/cross-site-scripting/SKILL.md` |
| BOLA / IDOR / mass assignment (`setattr` / BOPLA) | `red-team/web-and-application/authorization-and-idor/SKILL.md` |
| Outbound URL fetch / `169.254.169.254` / PDF SSRF | `red-team/web-and-application/ssrf/SKILL.md` |
| JWT / OAuth / OIDC / SAML / WebAuthn | `red-team/web-and-application/jwt-attacks/SKILL.md` |
| Active Directory / Kerberos / ADCS / NTLM | `red-team/network-ad-and-endpoint/active-directory-kerberos-attacks/SKILL.md` |
| Binary triage / Ghidra / IDA reversing | `red-team/binary-and-exploit-development/static-reverse-engineering/SKILL.md` |
| Rust `unsafe` / FFI (`from_raw_parts`) or Go `cgo`/races | `red-team/binary-and-exploit-development/rust-unsafe-and-ffi-security/SKILL.md` |
| AWS / Azure / GCP / K8s / GitHub Actions OIDC | `red-team/cloud-container-supply-chain/aws-attacks/SKILL.md` |
| Prompt injection / OCR multimodal / RAG / MCP tool agency | `red-team/ai-and-llm/agentic-ai-and-mcp-security/SKILL.md` |
| ERC-4626 vault inflation & rounding (`previewWithdraw`) | `red-team/blockchain/erc4626-vault-inflation-and-rounding-audit/SKILL.md` |
| Solidity / Solana Anchor / EIP-712 / DeFi smart contracts | `red-team/blockchain/smart-contract-audit/SKILL.md` |
| Write Semgrep / CodeQL / Nuclei / fuzzer / IDAPython tool | `red-team/security-assessment-tooling-and-automation/README.md` |
| Write Sigma rule or SIEM / KQL / SPL detection | `blue-team/detection-and-monitoring/sigma-rule-authoring/SKILL.md` |
| PowerShell 4104 / missing ScriptBlock or Sysmon telemetry | `blue-team/malware-analysis/fileless-and-living-off-the-land-detection-script-telemetry/SKILL.md` |
| Active ransomware / RaaS / BEC / cloud incident | `blue-team/incident-response/ransomware-response/SKILL.md` |
| Disk / Windows EVTX-Registry / Volatility 3 RAM | `blue-team/digital-forensics/windows-artifact-forensics/SKILL.md` |
| Parse Chromium/Firefox SQLite + `-wal` preserving SHA-256 | `blue-team/security-automation-and-tool-development/sqlite-wal-and-browser-artifact-scripting/SKILL.md` |
| Write OPA Rego v1 Terraform `tfplan` / Checkov policy | `blue-team/security-automation-and-tool-development/iac-rego-opa-and-checkov-policy-development/SKILL.md` |
| Write `pySigma` / YARA-X / Zeek / EVTX / VQL / SOAR script | `blue-team/security-automation-and-tool-development/README.md` |
| Prioritize CVEs / EPSS / CVSS / CISA KEV / FP triage | `blue-team/vulnerability-and-hardening/cvss-epss-and-risk-scoring/SKILL.md` |
| Review Flask / FastAPI / Pydantic / SQLAlchemy code | `blue-team/application-security/flask-and-fastapi-security/SKILL.md` |
| Review Django / Express / Next.js / Spring / .NET / Go code | `blue-team/application-security/README.md` |

## All 19 Family Routes

### Red Team (`red-team/`)

| Family Folder | When to Open `<family>/README.md` |
|---|---|
| [`web-and-application`](red-team/web-and-application/README.md) | Web apps, REST/GraphQL/gRPC APIs, auth/SSO, injection, smuggling, cache, Zip-Slip, PDF SSRF |
| [`network-ad-and-endpoint`](red-team/network-ad-and-endpoint/README.md) | Network protocols, Active Directory, Kerberos, ADCS, Windows/Linux/macOS privilege boundaries |
| [`binary-and-exploit-development`](red-team/binary-and-exploit-development/README.md) | Reverse engineering, memory safety, heap/stack/kernel primitives, fuzzing, Rust/Go/Wasm boundaries |
| [`mobile-hardware-wireless-ics`](red-team/mobile-hardware-wireless-ics/README.md) | Android/iOS apps, UART/JTAG/firmware, Wi-Fi/BLE/SDR, CAN bus, Thread/Matter/Zigbee/MQTT, ICS/SCADA |
| [`cryptography-attacks`](red-team/cryptography-attacks/README.md) | AES-GCM/AEAD, padding oracles, RSA/ECC/lattices, PRNG/nonces, TLS/PKI, KMS envelope, PQC hybrids |
| [`cloud-container-supply-chain`](red-team/cloud-container-supply-chain/README.md) | AWS/Azure/GCP, IAM escalation, Kubernetes, containers, GitHub Actions OIDC, OCI/package supply chain |
| [`ai-and-llm`](red-team/ai-and-llm/README.md) | Direct/indirect/multimodal prompt injection, RAG poisoning, MCP/agentic tool scope, MITRE ATLAS, LoRA |
| [`blockchain`](red-team/blockchain/README.md) | Solidity, Solana/Anchor, Move, ERC-4626 vaults, EIP-712/ERC-4337 signatures, flash loans, oracles |
| [`osint-and-red-operations`](red-team/osint-and-red-operations/README.md) | Geolocation, archival/CDX, corporate registries, on-chain tracing, handle pivots, ROE scoping, reporting |
| [`security-assessment-tooling-and-automation`](red-team/security-assessment-tooling-and-automation/README.md) | **Build custom assessment tools:** Nuclei v3, Semgrep taint, CodeQL, Burp Montoya, libFuzzer/cargo-fuzz, IDAPython, Ghidra, Frida |

### Blue Team (`blue-team/`)

| Family Folder | When to Open `<family>/README.md` |
|---|---|
| [`detection-and-monitoring`](blue-team/detection-and-monitoring/README.md) | Detection engineering, Sigma/YARA authoring, SPL/KQL/EQL, DNS/beacon analytics, K8s & OT passive monitoring |
| [`threat-intelligence-and-hunting`](blue-team/threat-intelligence-and-hunting/README.md) | CTI lifecycle, IOC scoring, hypothesis hunting, Diamond Model clustering, GenAI/agent telemetry hunting |
| [`incident-response`](blue-team/incident-response/README.md) | IR playbooks, ransomware & RaaS extortion, BEC, web/cloud IR, token/krbtgt revocation, DDoS mitigation |
| [`digital-forensics`](blue-team/digital-forensics/README.md) | Disk/MFT/USN, Windows Registry/Prefetch/EVTX, Linux/macOS, Volatility 3 memory, PCAP, M365/Entra UAL |
| [`malware-analysis`](blue-team/malware-analysis/README.md) | IR sample triage, static/dynamic analysis, config extraction, Go/Rust binaries, Android LAMDA features & drift |
| [`vulnerability-and-hardening`](blue-team/vulnerability-and-hardening/README.md) | CVSS/EPSS/KEV prioritization, false-positive verification, CIS baselines, AD/Linux/Cloud/Zero-Trust mTLS hardening |
| [`application-security`](blue-team/application-security/README.md) | Secure code review, Flask/FastAPI, Django, Express, Next.js, Spring, ASP.NET, Rails, Go, threat modeling |
| [`purple-team-and-program`](blue-team/purple-team-and-program/README.md) | Atomic/purple-team validation, remediation SLAs, NIST CSF / ISO 27001 / CIS mapping, architecture & vendor risk |
| [`security-automation-and-tool-development`](blue-team/security-automation-and-tool-development/README.md) | **Build custom defensive tools:** `pySigma`, `yara-x`, Zeek, OCSF/ECS ETL, EVTX/SQLite/MFT/PCAP parsers, Volatility 3 plugins, VQL, OPA Rego, SOAR, SBOM |

## Task Disambiguation Rules

| Request Type | Route To | Do NOT Route To |
|---|---|---|
| "Use tool X / audit target for bug X" | Domain family (`web-and-application`, `digital-forensics`, etc.) | Tool-development families |
| "Write a custom script / plugin / rule / fuzzer / parser for X" | `security-assessment-tooling-and-automation` (Red) or `security-automation-and-tool-development` (Blue) | Operational-only playbooks |
| "Review/fix this Flask, Next.js, Spring, Go, or C# code" | `blue-team/application-security/<framework-slug>` or `secure-code-review` | Offensive payload sub-skills |
| "Is this scanner finding / VDP report a false positive?" | `blue-team/vulnerability-and-hardening/vulnerability-false-positive-verification` | Generic vulnerability summaries |
