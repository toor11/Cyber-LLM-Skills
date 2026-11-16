---
name: host-persistence-linux-and-macos-persistence
description: Linux and macOS persistence. Covers systemd units, cron, shell profiles, SSH keys, launchd agents and login items on Unix-like hosts. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: network-ad-and-endpoint
tier: leaf
triggers: ["linux persistence", "macos persistence", "systemd persistence", "cron persistence"]
cwe: [CWE-269]
owasp: []
attack: [T1547]
capec: [CAPEC-563]
related: [host-persistence, host-persistence-registry-and-service-persistence, host-persistence-scheduled-and-wmi-persistence, network-recon-and-port-scanning]
parent: host-persistence
---

# Host Persistence Linux and Macos Persistence - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Network, Active Directory and Endpoint`](../README.md) | Tier: **leaf** | Paired Counterpart: [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md)

## Mechanism and Preconditions

On Linux the durable surfaces are systemd units and timers, cron, `rc.local`, shell profile scripts, `ld.so.preload`, and per-user `~/.config/autostart`; on macOS they are launch agents and daemons, login items, configuration profiles, periodic scripts and login hooks. The unifying property is that each surface executes content from a path, so persistence is always a pair: a configuration entry and a path that the entry loads. The methodology reads both halves and checks whether the path is writable by the identity that will execute it.

- **CWE-269 (Improper Privilege Management):** The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the evidence is not yet pinned to this specific variant **THEN** open the class skill [`host-persistence`](../host-persistence/SKILL.md) first and return here once the variant conditions match (1 hop)
2. **IF** the host is Linux with systemd **THEN** units and timers in `/etc/systemd/system` are the primary surface; user units in `~/.config/systemd/user` matter for per-user persistence
3. **IF** the host is macOS **THEN** launch agents in `~/Library/LaunchAgents` need no administrator rights, while launch daemons in `/Library/LaunchDaemons` do
4. **IF** the mechanism must survive a package upgrade **THEN** a path under `/usr/local` survives while a path in a package directory may be replaced; that difference matters for durability
5. **IF** the mechanism must run as root **THEN** system units and launch daemons are the root-capable surfaces; cron for root is the alternative
6. **IF** the question is *detect, hunt, contain or harden* rather than *prove and scope* **THEN** pivot to the paired Blue skill [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) and keep this file for attack-path evidence only
7. **IF** required preconditions for `host-persistence-linux-and-macos-persistence` are absent after inspecting the evidence **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a fit

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Windows autostart surfaces | [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) | Registry and service mechanisms |
| Windows trigger-based mechanisms | [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) | Tasks and WMI |
| The unit file is writable and enables escalation | [`linux-privilege-escalation-cron-and-systemd`](../linux-privilege-escalation-cron-and-systemd/SKILL.md) | Escalation rather than persistence |
| The mechanism is in the directory | [`active-directory-persistence`](../active-directory-persistence/SKILL.md) | AD-level durability |
| Need the class-level branch table first | [`host-persistence`](../host-persistence/SKILL.md) | Parent triage before variant specifics |
| Need a second probe set or SIEM syntax | [`PAYLOADS.md`](PAYLOADS.md) | Grouped non-destructive probes with expected differentials |
| Need exact flags and one validation script | [`TOOLS.md`](TOOLS.md) | Authorized lab harness, not an attack runbook |
| Need disclosed cases and root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents with preconditions intact |
| Need the log source and field names | [`DETECTION.md`](DETECTION.md) | Event ids, fields, and query shapes |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate by mechanism and by identity.** System-scope surfaces: `/etc/systemd/system`, `/etc/cron.d`, `/etc/rc.local`, `/etc/ld.so.preload`, `/etc/profile.d`. Per-user surfaces: `~/.config/autostart`, `~/.config/systemd/user`, `~/.bashrc`. macOS: `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `~/Library/LaunchAgents`, `/etc/periodic`. Each executes as a specific identity.
2. **Establish package or configuration-management provenance.** `dpkg -S` or `rpm -qf` on Linux, `pkgutil --file-info` on macOS. An entry not owned by a package and not generated by the configuration-management tool is the candidate.
3. **Check the writability of the loaded path.** The persistence is only as strong as the path's protection. A unit loading a script from a group-writable directory can be changed by anyone in that group, which is also the remediation target.
4. **Baseline against a reference image.** Autostart populations are stable per image. A diff gives a short candidate list and doubles as the remediation checklist.
5. **State the proof and stop.** Proof is the configuration entry, the package provenance, and the path's permissions. Forcing a service restart to observe execution is a state change and is not required.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| systemd unit not owned by any package | Proves boot-time execution outside distribution management; any systemd host. |
| `/etc/ld.so.preload` entry | Proves a library is loaded into every dynamically linked process, the broadest possible persistence; any Linux host. |
| `~/.config/autostart` `.desktop` file | Proves per-user session autostart without administrator rights; any Linux desktop. |
| launchd plist in `~/Library/LaunchAgents` | Proves per-user autostart on macOS at login, with no administrator rights; any macOS host. |
| `/Library/LaunchDaemons` plist not owned by a package | Proves boot-time execution as root on macOS outside any installer; any macOS host. |

## Worked Contrast

**Weak configuration — a launch agent loading a script from a group-writable user directory:**

```bash
# ~/Library/LaunchAgents/com.vendor.agent.plist runs ~/bin/agent.sh every 60s
ls -l ~/bin/agent.sh
# -rwxrwxr-x user staff  -> any process in the user's context can rewrite it,
# and the agent reloads it on the next interval
```

**Hardened configuration — agent loads a root-owned script from a protected path:**

```bash
sudo install -o root -g wheel -m 0755 ~/bin/agent.sh /usr/local/libexec/agent.sh
# repoint ProgramArguments in the plist to /usr/local/libexec/agent.sh, then reload
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.vendor.agent.plist 2>/dev/null
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.vendor.agent.plist
# verification: ls shows root ownership and no group write on the loaded script
```

**Why this matters:** persistence is a configuration entry plus a loaded path, so the control is the path's ownership and mode, and the verification is reading both back rather than waiting for a reload.

## When It Is NOT This Issue

- **A distribution-owned unit file.** Package-provided units are expected; provenance separates them from additions.
- **A per-user autostart entry in the user's own session.** A user starting their own program at login is not a privilege boundary crossing.
- **A disabled or masked unit.** `systemctl is-enabled` reports the state; a masked unit cannot start and is not an active mechanism.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `host-persistence-linux-and-macos-persistence` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `host-persistence-linux-and-macos-persistence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: host-persistence-linux-and-macos-persistence
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1547]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) - Blue Detection/Defense Counterpart
- [`host-persistence`](../host-persistence/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`host-persistence-registry-and-service-persistence`](../host-persistence-registry-and-service-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`host-persistence-scheduled-and-wmi-persistence`](../host-persistence-scheduled-and-wmi-persistence/SKILL.md) - Network, Active Directory and Endpoint (leaf)
- [`network-recon-and-port-scanning`](../network-recon-and-port-scanning/SKILL.md) - Network, Active Directory and Endpoint (core)
- [`service-enumeration`](../service-enumeration/SKILL.md) - Network, Active Directory and Endpoint (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `host-persistence-linux-and-macos-persistence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1547`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/oxdf (11), CYBER_CPT/expku (8), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
