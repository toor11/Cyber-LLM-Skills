# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-forensic-artifact-parser-development`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative artifact-parsing failures, each with the artefact that proves the diagnosis.

## Case 1: Prefetch run count reported as zero

- **Surface & Preconditions:** a parser reads the run count at offset 208 for every Prefetch file.
- **Root cause & impact:** versions 30/31 have two file-information layouts. With the 212-byte variant, offset 208 holds unrelated bytes and the true count sits at 200, so busy executables are reported as never run — the opposite of the forensic conclusion.
- **Verification & fix:** branch on the metrics-array offset (296 versus 304) which follows the file-information block, and record the chosen layout in the output.

## Case 2: Registry value from an hour before the incident

- **Surface & Preconditions:** a hive is copied without its `.LOG1`/`.LOG2` transaction logs.
- **Root cause & impact:** the last written cells live in the logs until flushed. The parsed hive shows an older `Run` key state, and the persistence mechanism appears not to exist yet at the time of compromise.
- **Verification & fix:** copy and apply transaction logs on the copy, and report `logs_applied: true|false` with every hive parse.

## Case 3: Every file looks created at the same instant

- **Surface & Preconditions:** a `$MFT` parser collapses the MACB set into one "timestamp" column.
- **Root cause & impact:** four distinct attribute timestamps become one, so file creation, modification, and metadata change are indistinguishable — and a timestomp that touched only `$STANDARD_INFORMATION` vanishes from the report.
- **Verification & fix:** emit one row per attribute timestamp with the attribute type recorded, and let the timeline layer decide how to display them.

## Case 4: The evidence changed during analysis

- **Surface & Preconditions:** a hive or database is opened directly from the mounted evidence.
- **Root cause & impact:** the parser's library may write (journal replay, lock files, log checkpointing), so the evidence hash no longer matches acquisition and the derived report is not attributable.
- **Verification & fix:** copy to a working directory, hash before and after, and fail on any drift.
