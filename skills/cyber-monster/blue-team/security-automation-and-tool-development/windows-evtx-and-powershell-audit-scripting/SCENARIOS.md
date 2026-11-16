# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-evtx-and-powershell-audit-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative EVTX parsing failures, each with the artifact that proves the diagnosis.

## Case 1: A long script appears as a one-line stub

- **Surface & Preconditions:** a 4104 reassembler runs over a log containing an encoded multi-fragment script; the emitted script is the first 8 KB only.
- **Root cause & impact:** the implementation defaulted a missing `MessageTotal` to `1`, so fragment 1 satisfied the completeness test and the block was emitted immediately. The rest of the script was discarded as duplicate work.
- **Verification & fix:** treat `MessageTotal` of `0`/absent as unknown, compare against the highest `MessageNumber` seen, and emit at EOF with an explicit reason instead of forcing completion.

## Case 2: Two hosts' scripts merged into one

- **Surface & Preconditions:** fragments are keyed on `ScriptBlockId` alone across a merged multi-host log.
- **Root cause & impact:** a GUID collision or a copied script produces fragments with the same ID from different hosts; the joined text interleaves two scripts and looks like one malicious concatenation that never existed.
- **Verification & fix:** key on `(Computer, ScriptBlockId)` and record the computer on every emitted block.

## Case 3: Parse aborts at a carved chunk

- **Surface & Preconditions:** a disk image yields a partially overwritten `.evtx`; the parser calls `ET.fromstring` without a guard.
- **Root cause & impact:** the first damaged record raises and terminates the run, so the thousands of intact records after it are never read — the analyst concludes the log is empty.
- **Verification & fix:** wrap per-record parsing, increment a corrupt counter, and report it beside the emitted count. A non-zero corrupt count is expected on carved evidence.

## Case 4: Live read fails on a file the service holds

- **Surface & Preconditions:** a collection script opens `C:\Windows\System32\winevt\Logs\Security.evtx` for reading on a running host.
- **Root cause & impact:** the EventLog service holds the active file; the read either fails or returns a stale prefix, so recent events are missing with no error that points at the cause.
- **Verification & fix:** use `Get-WinEvent -FilterHashtable` for live collection, or copy the file with the service stopped/volume-shadowed for offline parsing.
