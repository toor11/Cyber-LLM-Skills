# Detection Queries and Telemetry Artifacts

> Sub-skill: [`yara-rule-authoring`](SKILL.md) | Family: **Detection and Monitoring**

Compile, corpus-precision and scan artefacts owned by `yara-rule-authoring`. These evaluate the rule itself against benign and positive corpora rather than against live telemetry. Every class states the expected hit and the false-positive note to clear first.

## Class 1 — Compile under the deployed engine

Expected hit: zero errors under the engine that will run the rule. YARA-X rejects constructs legacy YARA accepted, so an engine mismatch is a deployment failure rather than a style issue.

```bash
yr check rules/
```

```bash
yr compile --output rules.yarc rules/
```

False-positive note: a rule that compiles under legacy `yara` is not thereby valid for `yr`; keep both checks in CI while the fleet is mixed.

## Class 2 — Precision against a benign corpus

Expected hit: zero or near-zero matches over a clean system corpus and a known-good build output set. This is the only measurement that separates a detection from a coincidence.

```bash
yr scan --output-format ndjson rules/family.yar /usr/bin | jq -r '.rules[].identifier' | sort | uniq -c | sort -rn
```

```bash
yr scan --output-format ndjson rules/family.yar /opt/build/artifacts \
  | jq -c '{path: .path, rules: [.rules[].identifier]}'
```

False-positive note: a rule matching a single file in a benign corpus is often matching a legitimate dual-use tool; review the matched string with `--print-strings` before tightening the condition.

## Class 3 — Coverage over the positive set

Expected hit: every sample in the family set matches, and samples from adjacent families do not. Coverage of one build only is a signature, not a family rule.

```bash
yr scan --print-strings --output-format ndjson rules/family.yar samples/positive/ \
  | jq -c '{path: .path, rules: [.rules[] | {id: .identifier, strings: (.matches // [] | length)}]}'
```

```bash
# Negative control: adjacent-family samples must stay unmatched.
yr scan --output-format text rules/family.yar samples/adjacent/ \
  && echo "UNEXPECTED MATCH in adjacent family" || echo "ok: adjacent family clean"
```

False-positive note: a sample that fails to match only because it is packed is a corpus problem, not a rule gap; record packing state per sample before concluding the rule misses the family.

## Class 4 — String width and boundary behaviour

Expected hit: matches located at the UTF-16LE encoding for compiled Windows strings, and at word boundaries where `fullword` is used. A rule matching only `ascii` misses every compiled-in literal.

```bash
yr scan --print-strings --output-format text rules/family.yar samples/positive/build.exe
```

```bash
# Compare: a rule that matches only in ascii mode on the same sample.
yr scan --print-strings rules/ascii_only.yar samples/positive/build.exe || echo "no ascii-only match"
```

False-positive note: a `wide` string can match coincidentally inside unrelated binary data at low probability; `fullword` reduces that but does not eliminate it, so pair with a structural condition.

## Class 5 — Memory and process-image scanning

Expected hit: matches in the unpacked image where the code is resident, with an explicit statement about regions that may be paged out.

```bash
yr scan --output-format ndjson rules/family.yar memory_dump.raw \
  | jq -c '{rules: [.rules[].identifier]}'
```

```powershell
# Scope a scan to a specific directory of extracted process images rather than all of memory.
yr scan --recursive --output-format ndjson rules/family.yar C:\Cases\case-01\proc\ | Out-File hits.ndjson
```

False-positive note: a negative result on a memory image proves only that the bytes were not resident; pages on disk are not in the image, so absence is unproven rather than exculpatory.

## Class 6 — Structural conditions and threshold calibration

Expected hit: structural predicates (`pe.number_of_sections`, `pe.imphash`, entropy) that hold across family builds while excluding the benign corpus.

```yaml
// Calibration fragment: measure before committing a threshold.
condition:
  uint16(0) == 0x5A4D
  and pe.number_of_sections <= 5
  and math.entropy(0, filesize) > 6.5
  and 2 of ($api_*)
```

False-positive note: entropy thresholds are sensitive to compression and to legitimate installers; a rule that separates on entropy alone will match every packed benign installer in the corpus.

## Deployment Gates

- Validate against >=1 positive replay and a 7-day benign production baseline.
- Document known benign admin tools or scanners before enabling alerting.
- Record the engine (`yr` versus legacy `yara`) and its version with every deployed rule; module fields and built-ins differ between them.
