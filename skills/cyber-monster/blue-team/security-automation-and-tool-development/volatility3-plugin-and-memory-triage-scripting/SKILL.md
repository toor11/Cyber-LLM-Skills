---
name: volatility3-plugin-and-memory-triage-scripting
description: "Develops Volatility 3 (`volatility3.framework`, never deprecated Volatility 2) Python plugins and automated RAM triage wrappers: `PluginInterface`, `TreeGrid` typed output, VAD RWX/unbacked code region anomaly scoring, and cross-checking `pslist` vs `psscan`. Use when writing memory-forensics plugins or batch RAM triage tools."
family: security-automation-and-tool-development
tier: core
triggers: ["volatility3 plugin", "volatility3 python api", "treegrid volatility", "memory triage script"]
cwe: [CWE-778]
owasp: []
attack: []
capec: []
related: [sigma-pipeline-and-backend-development, yara-and-yara-x-scanner-engineering, zeek-script-and-notice-development, suricata-lua-and-rule-qa-tooling]
corpus_sparse: true
---

# Volatility 3 Plugin and Memory Triage Scripting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Security Automation and Tool Development`](../README.md) | Tier: **core** | Paired Counterpart: [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Volatility 3 reads a memory image through a layered address-space stack: a translation layer built from an Intel layer plus a symbol table, then operating-system plugins that walk kernel structures using symbols resolved from an ISF (Intermediate Symbol Format) bundle. A plugin is a class, not a script: it subclasses `interfaces.plugins.PluginInterface`, declares `_version` and `_required_framework_version`, returns `Requirement` objects from `get_requirements()` (a `ModuleRequirement` for the kernel symbol table, `VersionRequirement`/`PluginRequirement` for any other plugin it calls), and returns a `renderers.TreeGrid` whose column types drive rendering. Two consequences matter operationally. First, every plugin depends on symbols matching the image's exact kernel build — a wrong or mismatched ISF bundle yields empty results rather than an error, which is why an empty `pslist` must be treated as a symbol problem until proven otherwise. Second, plugin-to-plugin calls need version requirements, otherwise a future change to the called plugin breaks the caller silently. Triage logic then rests on cross-view comparison: `pslist` walks the active process list (fast, misses terminated and DKOM-hidden processes), `psscan` pools the memory for `_EPROCESS` signatures (slower, finds unlinked processes), and `malfind` finds VAD regions that are executable and either unbacked or anomalously private — the difference between the views is the finding.

- **CWE-778 (Insufficient Logging):** a triage run that reports "no anomalies" because symbols failed to load is a memory image that was never actually examined.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** you are writing a plugin **THEN** subclass `interfaces.plugins.PluginInterface`, set `_version` and `_required_framework_version`, return requirements including a `ModuleRequirement(name="kernel")`, and return `renderers.TreeGrid([(name, type), ...], generator)`.
2. **IF** your plugin calls another plugin **THEN** declare a `VersionRequirement` (or `PluginRequirement`) for it; the framework will refuse to run otherwise, and that refusal is the point.
3. **IF** a plugin returns zero rows **THEN** check the symbol table before the logic — verify the ISF bundle matches the image build, and confirm the translation layer satisfied its requirements.
4. **IF** you are doing triage rather than plugin development **THEN** compare `windows.pslist` against `windows.psscan` and `windows.malfind` against `windows.vadinfo`, and report the discrepancies rather than a single plugin's output.
5. **IF** you need the paired operational/counterpart perspective **THEN** open [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md).
6. **IF** required preconditions for `volatility3-plugin-and-memory-triage-scripting` are absent after checking the input **THEN** **STOP** and classify the pattern as a verified non-finding rather than forcing a guess.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need runnable plugin and triage commands | [`QUERIES.md`](QUERIES.md) | Plugin skeleton, `vol -f` invocations, cross-view commands |
| Need CLI syntax, flags, and framework references | [`TOOLS.md`](TOOLS.md) | `vol` flags, requirement classes, symbol handling |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Symbol-mismatch and hidden-process incidents |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Evidence-handling handoff for memory images |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Stack / Schema:** Volatility 3 (`volatility3.framework.interfaces.plugins.PluginInterface`, `requirements.VersionRequirement`, `renderers.TreeGrid`, ISF symbol tables), never Volatility 2
- **Mandatory Self-Validation Command:** `python -m py_compile vol_plugin.py; vol -f image.raw windows.pslist`

1. **Confirm the inputs.** Identify the image format and OS build, whether a matching symbol bundle is available locally, and which plugins the triage depends on. Confirm the image is a copy with a recorded hash — a memory image is volatile evidence and the plugin run must be reproducible against the same bytes.
2. **Choose the branch.** Plugin development → requirements plus `TreeGrid`. Triage → fixed command set with cross-view comparison. Automation → a wrapper that runs each plugin, captures the row counts, and fails loudly when a run returns zero rows for a plugin that should never be empty.
3. **Define how to validate the plugin or wrapper.** `python -m py_compile` for the module; then run the plugin against a known image and check the `TreeGrid` column set and types match what downstream code expects; then run the cross-view differential (`pslist` vs `psscan`) and assert the discrepancy list is produced rather than an empty report.
4. **Name the stop condition.** Stop when symbol resolution fails (empty output across plugins, not just one), when a required plugin's version requirement is unsatisfied, when a run produces zero rows for a plugin that cannot legitimately be empty, or when the wrapper reports "clean" while a sibling plugin errored.
5. **State what counts as a working tool.** A working plugin returns a `TreeGrid` with declared column types and satisfies every declared requirement; a working wrapper exits `0` only when every plugin ran with a non-zero row count where rows are expected, and it prints the per-plugin counts so a silent symbol failure cannot look like a clean result.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `_required_framework_version` plus `get_requirements()` returning a `ModuleRequirement` | Proves the plugin is bound to a specific framework generation and kernel symbol table |
| `renderers.TreeGrid([("PID", int), ...], generator)` | Proves output is typed, so renderers and downstream parsers agree on the schema |
| `VersionRequirement(name="pslist", component=..., version=(2, 0, 0))` | Proves a plugin-to-plugin dependency is declared and will be checked before running |
| `pslist` vs `psscan` set difference on PID | Proves the process-list view is incomplete; unlinked processes are the finding |
| `malfind` RWX/unbacked VAD regions cross-checked with `vadinfo` | Proves suspicious memory regions exist as address-space facts, not a single heuristic's opinion |

## Worked Contrast

**Naive / Fragile Artifact (AVOID):**

```python
# ANTI-PATTERN: no version metadata, no requirements, no TreeGrid, and it silently
# returns nothing when the symbol table is missing.
class ProcessLister:
    def __init__(self, context):
        self.context = context

    def run(self):
        try:
            kernel = self.context.modules[self.context.config["primary"]]
            for proc in kernel.object("PsActiveProcessHead"):
                print(proc)
        except Exception:
            return
```

**Production-Grade Starter Skeleton (USE):**

```python
# vol_plugin.py - Volatility 3 plugin skeleton with declared requirements and typed output
from typing import Generator, List

from volatility3.framework import interfaces, renderers, requirements
from volatility3.framework.interfaces import configuration
from volatility3.plugins.windows import pslist


class ProcessAnomalySummary(interfaces.plugins.PluginInterface):
    """Summarise process-tree anomalies from the active process list."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist",
                component=pslist.PsList,
                version=(2, 0, 0),
            ),
        ]

    def _generator(self) -> Generator:
        kernel = self.context.modules[self.config["kernel"]]
        for proc in pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
        ):
            try:
                name = proc.ImageFileName.cast(
                    "string", max_length=proc.ImageFileName.vol.count, errors="replace"
                )
                ppid = proc.InheritedFromUniqueProcessId
                exit_time = proc.get_exit_time()
            except Exception:
                continue
            yield (0, (int(proc.UniqueProcessId), int(ppid), name, exit_time or 0))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("PPID", int), ("ImageFileName", str), ("ExitTime", int)],
            self._generator(),
        )
```

**Why this matters:** the requirements are declared so the framework refuses to run against an incompatible symbol table, and the output is a typed `TreeGrid` — the failure mode becomes a visible framework error instead of an empty, misleading result.

## When It Is NOT This Issue

- **Every plugin returns zero rows** — symbol table mismatch or the wrong translation layer, not "the image is clean". Check symbol resolution before reading anything into the emptiness.
- **`pslist` shows fewer processes than `psscan`** — expected: `psscan` pool-scans for terminated and unlinked processes. The difference is the finding, not a plugin bug.
- **`malfind` flags hundreds of regions** — browser JIT pages and .NET code heaps are RWX by design; triage by module backing and parent process before treating a region as injected.
- **A plugin fails with `PluginRequirementException`** — a declared requirement is unsatisfied (usually a version); that is the framework working as intended, so fix the requirement rather than removing it.
- **Volatility 2 profiles or plugins are referenced** — Volatility 3 uses ISF symbols and classes; a v2 profile has no equivalent, and the migration is a rewrite.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- NEVER present a Volatility 2 profile or plugin as usable in Volatility 3; the symbol and plugin models are different.
- NEVER remove a `VersionRequirement` to make a plugin run — the requirement exists because the called plugin's interface is versioned.
- NEVER report an empty plugin result as evidence of a clean image without confirming symbol resolution.
- NEVER claim `malfind` output proves injection on its own; it must be corroborated with module backing and process context.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Image format/build, symbol availability, and required plugin set for `volatility3-plugin-and-memory-triage-scripting` were confirmed, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** The plugin, requirement set, or triage wrapper is specific and runnable (no generic 'analyze memory' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Tool / Rule Deliverable: volatility3-plugin-and-memory-triage-scripting
- **Target Stack & Schema**: Volatility 3 PluginInterface with declared requirements, TreeGrid output, ISF symbols
- **Safety, Scope & Exit-Code Guards**: [Read-only image access, symbol verification, per-plugin row counts, exit codes 0/1/2]
- **False-Positive & Edge-Case Handling**: [Symbol mismatch, expected pslist/psscan divergence, RWX JIT regions]
- **Implementation**:
  [Runnable plugin or triage wrapper following the Starter Skeleton]
- **Self-Validation Command**: `python -m py_compile vol_plugin.py; vol -f image.raw windows.pslist`
```

## Related Sub-Skills

- [`semgrep-rule-engineering`](../../../red-team/security-assessment-tooling-and-automation/semgrep-rule-engineering/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`windows-forensic-artifact-parser-development`](../windows-forensic-artifact-parser-development/SKILL.md) - Disk-side counterparts to these memory artifacts
- [`yara-and-yara-x-scanner-engineering`](../yara-and-yara-x-scanner-engineering/SKILL.md) - Pattern rules for regions `malfind` surfaces
- [`velociraptor-vql-artifact-development`](../velociraptor-vql-artifact-development/SKILL.md) - Live-endpoint collection that complements offline image analysis
- [`super-timeline-and-plaso-postprocessing-scripting`](../super-timeline-and-plaso-postprocessing-scripting/SKILL.md) - Places memory-derived timestamps on the timeline
- [`windows-evtx-and-powershell-audit-scripting`](../windows-evtx-and-powershell-audit-scripting/SKILL.md) - Execution evidence that corroborates process findings

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `volatility3-plugin-and-memory-triage-scripting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
