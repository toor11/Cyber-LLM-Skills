# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`volatility3-plugin-and-memory-triage-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative memory-triage failures, each with the artifact that proves the diagnosis.

## Case 1: "The image is clean" — it was never parsed

- **Surface & Preconditions:** a triage wrapper runs four plugins, collects their JSON, and reports zero findings across the board.
- **Root cause & impact:** no ISF symbol bundle matched the image build, so every plugin returned an empty result set without raising. The report reads as "no malicious processes", which is the worst possible conclusion for an unexamined image.
- **Verification & fix:** assert a non-zero row count for plugins that cannot legitimately be empty (`pslist`, `psscan`) and fail the run otherwise; record the symbol path in the report.

## Case 2: Hidden process found by lucky coincidence

- **Surface & Preconditions:** triage relies solely on `windows.pslist`.
- **Root cause & impact:** a process unlinked from the active list never appears in `pslist`; only `psscan`'s pool scan finds it. A single-view triage reports a partially hidden intrusion as clean.
- **Verification & fix:** always compute the `psscan` minus `pslist` PID differential and report it explicitly, including create/exit times to separate genuinely terminated processes from unlinked live ones.

## Case 3: malfind flood treated as mass injection

- **Surface & Preconditions:** `malfind` returns dozens of RWX private regions on a workstation with browsers and a .NET application.
- **Root cause & impact:** JIT compilers legitimately allocate executable private memory, so the raw `malfind` list is dominated by benign regions; treating it as confirmed injection produces a false incident and wastes the response window.
- **Verification & fix:** corroborate each candidate with `vadinfo` (module backing, protection changes) and the owning process's module list before escalating.

## Case 4: Plugin works locally, fails in the wrapper

- **Surface & Preconditions:** a custom plugin calls `pslist.PsList` without a `VersionRequirement`.
- **Root cause & impact:** the framework raises a requirement exception (or, worse, the plugin works until the called plugin changes), so the wrapper's error handling swallows it and reports a partial triage.
- **Verification & fix:** declare `VersionRequirement`/`PluginRequirement` for every cross-plugin call and let the exception surface as a hard failure in the wrapper's exit code.
