# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`yara-and-yara-x-scanner-engineering`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative signature-engineering failures, each with the artifact that proves the diagnosis.

## Case 1: One rule owns the whole scan budget

- **Surface & Preconditions:** a fleet scan over a 40 GB clean-ware corpus completes in four hours; a second scan over a 400 MB sample set takes six.
- **Root cause & impact:** one rule alternates between two long literals, so atom extraction falls back to a one-byte atom that appears in nearly every file. The scanner spends its time verifying candidates that never match.
- **Verification & fix:** `yr scan --profiling` names the rule and its time share. Rewrite the alternation as two separate strings with an `any of them` condition, or guard the regex behind `filesize < 5MB and pe.is_pe`.

## Case 2: Ported rule fails to compile under YARA-X

- **Surface & Preconditions:** a rule set maintained for classic YARA is moved to `yr compile` during a scanner migration.
- **Root cause & impact:** YARA-X enforces stricter regular-expression escaping, so patterns classic YARA treated as literal characters are compile errors. The directory scan then silently covers fewer rules than the team believes.
- **Verification & fix:** treat `yr compile` as a hard CI gate. Where a pattern was relying on relaxed parsing, either fix the escape or use `--relaxed-re-syntax` deliberately and record why.

## Case 3: Signature matches clean-ware installer

- **Surface & Preconditions:** a rule matches a packed installer stub by section entropy alone.
- **Root cause & impact:** the condition encodes "high entropy" as malicious, which every compressed installer satisfies. Alert volume spikes and the rule is disabled, losing real coverage.
- **Verification & fix:** add a discriminating structural term (`pe.imphash()`, a specific rich header, an import pair) and keep the entropy test as a supporting clause. Register the clean-ware sample as a permanent fixture.

## Case 4: Stale compiled ruleset

- **Surface & Preconditions:** `yr scan -C rules.yarc` runs on a schedule from a CI cache.
- **Root cause & impact:** the `.yarc` artifact was compiled before the latest rule edit, so scan results describe an older rule revision and a newly added detection never fires.
- **Verification & fix:** key the cache on a hash of the rule tree, or recompile inside the same job. `-C` accepts a single compiled path, so multiple source files must be compiled into one artifact first.
