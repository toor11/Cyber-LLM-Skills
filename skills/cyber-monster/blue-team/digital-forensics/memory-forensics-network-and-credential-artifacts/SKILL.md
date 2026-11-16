---
name: memory-forensics-network-and-credential-artifacts
description: Memory network and credential artefacts. Covers recovering network connections, listening sockets and credential material from memory images. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: digital-forensics
tier: leaf
triggers: ["memory network artifacts", "credential extraction memory"]
cwe: [CWE-345]
owasp: []
attack: []
capec: [CAPEC-116]
related: [memory-forensics, memory-forensics-process-and-injection-analysis, disk-forensics-and-artifacts, windows-artifact-forensics]
parent: memory-forensics
---

# Memory Forensics Network and Credential Artifacts - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Digital Forensics`](../README.md) | Tier: **leaf** | Paired Counterpart: [`credential-dumping`](../../../red-team/network-ad-and-endpoint/credential-dumping/SKILL.md)

## Mechanism and Preconditions

Windows keeps every TCP and UDP endpoint as a pool-allocated kernel object (`_TCP_ENDPOINT`, `_TCP_LISTENER`, `_UDP_ENDPOINT`) linked into per-process handle tables but also reachable by pool-tag signature. `windows.netscan` pool-scans those structures instead of walking handle tables, so it recovers endpoints belonging to processes that have already exited and to drivers whose handle links were unlinked; `windows.netstat` walks the links and misses both. Credential material is recovered the same way: the SAM, SECURITY and SYSTEM hive images stay resident in kernel pool pages, so `windows.hashdump` can rebuild the bootkey from the in-memory SYSTEM hive and decrypt local NTLM verifiers, `windows.cachedump` decrypts MSCache v1 / DCC2 entries for domain logons, and `windows.lsadump` exposes LSA secrets including service account passwords, autologon `DefaultPassword` plaintext and the `DPAPI_SYSTEM` key. What these plugins cannot tell you: `netscan` attributes an endpoint to a PID only while the owning object still references it, so a row with PID `-` or `0` is a real socket with no provable owner; `hashdump` returning a hash never means an adversary read it, because every local account has one; and `cachedump` on a workgroup host has nothing to decrypt. Plugin names are version-sensitive — Volatility 3 2.26.2 (2025-09-25) moved malware plugins under `windows.malware.*` while `netscan`, `hashdump`, `cachedump` and `lsadump` stay in `windows.*`; 2.28.0 (2026-04-30) improved Windows 11 Intel detection, so an empty result on a newer build is often a symbol-coverage limit rather than an empty pool.

- **CWE-345 (Insufficient Verification of Data Authenticity):** The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match `memory-forensics-network-and-credential-artifacts` **THEN** start at parent class [`memory-forensics`](../memory-forensics/SKILL.md) first.
2. **IF** your artefact is a live host rather than a captured image **THEN** take the live-triage branch: capture the dump before touching the network stack, because every `netscan` run depends on pool objects that a reboot or a driver unload destroys.
3. **IF** the artefact is an image or a minidump **THEN** take the dead-box branch and resolve `windows.info` first; **IF** the KDBG or build number does not resolve **THEN** stop and report a symbol failure, never an empty result set.
4. **IF** the host is workgroup-joined, not domain-joined **THEN** skip `windows.cachedump` as a designed-empty source and rely on `hashdump` plus `lsadump`; treating the empty cachedump as evidence of no domain logon is a category error.
5. **IF** the image came from a host with an active memory-integrity or hypervisor-based protection layer **THEN** expect kernel pool pages to be absent or partially paged and record the coverage hole before interpreting any plugin output as complete.
6. **IF** telemetry source covering `netscan` or `hashdump` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`credential-dumping`](../../../red-team/network-ad-and-endpoint/credential-dumping/SKILL.md).
8. **IF** required preconditions for `memory-forensics-network-and-credential-artifacts` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`memory-forensics`](../memory-forensics/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need to prove injected code rather than a socket | [`memory-forensics-process-and-injection-analysis`](../memory-forensics-process-and-injection-analysis/SKILL.md) | VAD- and PEB-level corroboration lives there |

## Procedure

1. **Prove the evidence source and its integrity before any plugin runs.** Hash the image, record the acquisition tool and whether it was live or post-mortem, then run `windows.info` to capture the banner, build, KDBG offset and detected layer. An image whose symbols do not resolve, or whose build predates the symbol pack you hold, produces empty output that is indistinguishable from a quiet host — that is a source defect, not a finding.
2. **Choose the branch explicitly and write it down.** Live triage means you must sequence captures before the host changes state (`netscan` first, then hive-dependent credential plugins, then anything that triggers driver activity). A dead-box image means symbols first, then `windows.netscan` and `windows.netstat` side by side: the delta between the two is your unlinked-or-exited-socket population, and it exists only on the dead-box branch.
3. **Build a baseline-versus-probe differential on endpoints, not on counts.** Establish the host's expected listening set and its expected egress set from a clean capture of the same build and role, then compare the observed set of `(local port, protocol, image path)` and `(remote address, remote port)` tuples. A single capture has no baseline of its own, so an absolute count of connections proves nothing; the differential is the finding.
4. **Name the stop condition before you interpret anything.** Stop and declare `Inconclusive` when the KDBG or symbol table does not resolve, when the image is truncated mid-pool-page, when `netscan` returns rows whose PID column is uniformly unresolvable (symbol offset drift rather than absent sockets), or when the credential hives are paged out so `hashdump` cannot derive the bootkey. Do not downgrade any of these to "low confidence clean".
5. **State what counts as proof.** Proof is two structurally unrelated artefacts agreeing on the same host inside one UTC minute: a pool-scanned endpoint and an EDR or firewall flow record, or a `netscan` PID plus a `windows.dlllist` image path that resolves to a user-writable directory. For credential material, proof is a hash recovered from memory matching the same account's on-disk verifier exactly — an exact byte match, never "approximately equal" — because a near-match is a different password.

## Concrete Patterns

| Indicator / Artifact | Artifact class | What it proves |
|---|---|---|
| Foreign endpoint in `windows.netscan` whose PID resolves to no live `windows.pslist` entry | Kernel pool socket object | Proves a TCP/UDP endpoint existed in physical memory at capture time on Windows even though its EPROCESS had exited; proves the remote address and port, not which binary opened it |
| `LISTENING` row on a high port owned by an image under a user-writable directory | Listening socket plus VAD-mapped image path | Proves the process named in the PID column was accepting inbound connections on Windows at capture time, when `windows.dlllist` confirms the image path |
| Same RID present in `windows.hashdump` NTLM output and `windows.cachedump` DCC2 output | Resident SAM and SECURITY hive images | Proves that account's local verifier and cached domain verifier were both recoverable from this Windows image; proves nothing about who read them |
| Populated `DefaultPassword` field in `windows.lsadump` | LSA secrets in resident SECURITY hive | Proves autologon plaintext was configured on the Windows host and survived in memory — the value is the credential itself, not a hash requiring cracking |
| `windows.malfind` private executable VAD in the same PID that owns an outbound endpoint | Cross-artefact, process plus network | Proves one process held both injected code and a live socket on Windows; the co-location is the corroboration and neither half stands alone |
| `windows.netscan` empty while `windows.netstat` returns rows | Plugin-source divergence | Proves the pool-scan constraint set did not match the build's struct layout, i.e. a symbol problem on Windows, not absence of connections |

## Worked Contrast

**Weak / Noisy Triage Practice:**

```text
# ANTI-PATTERN: dump the image, run one plugin, report every ESTABLISHED row.
vol -f host.dmp windows.netscan > netscan.txt
grep ESTABLISHED netscan.txt          # every browser tab, every updater, every AV heartbeat
vol -f host.dmp windows.cachedump     # empty on a workgroup host -> read as "no domain logons"
# No windows.info, no symbol check, no baseline capture, no PID-to-image resolution.
# A zero-row netscan is reported as "no network activity" without asking whether symbols loaded.
```

**Verified Pool-Scan and Hive-Image Corroboration:**

```bash
#!/usr/bin/env bash
# memory-net-cred-diff.sh — symbol gate, socket differential, then credential scope.
set -euo pipefail
IMG="${1:?usage: $0 image.dmp}"

# 1. Symbol and layer gate: refuse to interpret output from an unresolved image.
vol -f "$IMG" windows.info > info.txt 2> info.err || { echo "INCONCLUSIVE: windows.info failed"; exit 2; }
grep -q "Kernel Base" info.txt || { echo "INCONCLUSIVE: no KDBG"; exit 2; }

# 2. Pool-scanned sockets, with the owning image resolved per PID.
vol -f "$IMG" windows.netscan > netscan.txt
vol -f "$IMG" windows.pslist --pid "$(awk 'NR>2 && $3=="LISTENING" {print $1; exit}' netscan.txt)" > owner.txt

# 3. Credential scope: which hive-derived sources are even populated?
for p in hashdump cachedump lsadump; do
  vol -f "$IMG" "windows.${p}" > "cred_${p}.txt" 2>/dev/null || true
  printf '%-12s %s rows\n' "$p" "$(grep -vc '^$' "cred_${p}.txt" || echo 0)"
done

# 4. Differential against the pre-recorded clean capture for this build and role.
comm -13 baseline_endpoints.txt <(awk 'NR>2 {print $5":"$6" "$3}' netscan.txt | sort -u)
```

**Why this matters:** the strong form gates every later plugin on a resolved kernel base, resolves each socket owner to an image path instead of trusting the PID column, reports credential source population as a scope fact rather than a verdict, and compares the endpoint set against a same-build baseline instead of reading a single capture as if it were its own control.

## When It Is NOT This Issue

- **Pool residue of a terminated updater or AV component:** `netscan` legitimately returns rows whose PID has exited, because the endpoint object outlives the process while the pool page is unreferenced. Before calling it C2, require a matching flow record or a user-writable owning image; otherwise it is ordinary teardown residue.
- **A listening socket on every host in the fleet:** agent, backup and remote-management services bind predictable high ports. Compare the same tuple across several hosts of the same role — if it is fleet-wide it is a baseline, not an implant.
- **`hashdump` output that includes RID 500, RID 501 or a `MACHINE$` account:** these verifiers exist whether or not anyone dumped them, and the empty-LM/empty-NT constants appear for accounts with blank or disabled passwords. Their presence is a property of the SAM image, not evidence of credential theft.
- **`lsadump` service and default-password fields:** managed service accounts and autologon-configured kiosks populate these by design. Treat a populated `DefaultPassword` as a configuration finding requiring a rotation action, not automatically as adversary collection.
- **A truncated or non-contiguous image:** if the acquisition dropped pool pages, `netscan` and the credential plugins return a partial population that reads like a clean subset. Record the acquisition method and any page gaps next to every negative result.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `netscan` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Symbol and layer confirmed:** `windows.info` resolved a kernel base and build, and the detected layer matches the acquisition format, before any other plugin was interpreted.
- [ ] **Acquisition mode recorded:** the image is labelled live or post-mortem, with tool, hash and any dropped pool pages noted beside the results.
- [ ] **Owner resolution performed:** every endpoint row cited in the finding was resolved to an owning PID and an image path, and rows with an unresolvable owner are labelled as such.
- [ ] **Credential source scope stated:** each of `hashdump`, `cachedump` and `lsadump` is reported as populated or structurally empty for this host's join type, never as a verdict.
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: memory-forensics-network-and-credential-artifacts
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-345 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`credential-dumping`](../../../red-team/network-ad-and-endpoint/credential-dumping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`memory-forensics`](../memory-forensics/SKILL.md) - Digital Forensics (flagship)
- [`memory-forensics-process-and-injection-analysis`](../memory-forensics-process-and-injection-analysis/SKILL.md) - Digital Forensics (leaf)
- [`disk-forensics-and-artifacts`](../disk-forensics-and-artifacts/SKILL.md) - Digital Forensics (core)
- [`windows-artifact-forensics`](../windows-artifact-forensics/SKILL.md) - Digital Forensics (flagship)
- [`linux-forensics`](../linux-forensics/SKILL.md) - Digital Forensics (core)

## Operating Notes

- **Branch before plugin:** the single largest source of wrong conclusions here is running `netscan` without a symbol gate, then reading an empty result as an empty host. Declare live versus dead-box and the symbol outcome in the output.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-345`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; memory plugins are read-only against the image and must never be pointed at a live host's physical memory without an approved acquisition plan.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctf_search (2), CYBER_CPT/gh_advisories (1), CYBER_CPT/atomic_red_team (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
